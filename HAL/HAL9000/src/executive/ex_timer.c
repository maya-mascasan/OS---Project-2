#include "HAL9000.h"
#include "ex_timer.h"
#include "iomu.h"
#include "thread_internal.h"
#include "synch.h"

typedef struct _EX_TIMER_SYSTEM_DATA
{
    LOCK        Lock;
    LIST_ENTRY  TimerList;
} EX_TIMER_SYSTEM_DATA, *PEX_TIMER_SYSTEM_DATA;

static EX_TIMER_SYSTEM_DATA m_exTimerData;

void
ExTimerSystemPreinit(
    void
    )
{
    memzero(&m_exTimerData, sizeof(EX_TIMER_SYSTEM_DATA));
    LockInit(&m_exTimerData.Lock);
    LockSetName(&m_exTimerData.Lock, "TimerList");
    InitializeListHead(&m_exTimerData.TimerList);
}

static
void
_ExTimerWakeWaitingThreads(
    INOUT   PEX_TIMER   Timer
    )
{
    PLIST_ENTRY pEntry;

    while ((pEntry = RemoveHeadList(&Timer->WaitingList)) != &Timer->WaitingList)
    {
        PTHREAD pThread = CONTAINING_RECORD(pEntry, THREAD, ReadyList);
        ThreadUnblock(pThread);
    }
}

static
void
_ExTimerTrigger(
    INOUT   PEX_TIMER   Timer,
    IN      QWORD       CurrentTimeUs
    )
{
    Timer->ExpirationCount++;

    if (Timer->Type == ExTimerTypeRelativePeriodic)
    {
        Timer->TriggerTimeUs = CurrentTimeUs + Timer->ReloadTimeUs;
    }

    _ExTimerWakeWaitingThreads(Timer);
}

void
ExTimerSystemTick(
    void
    )
{
    INTR_STATE oldState;
    PLIST_ENTRY pEntry;
    QWORD currentTimeUs;

    currentTimeUs = IomuGetSystemTimeUs();
    LockAcquire(&m_exTimerData.Lock, &oldState);

    for (pEntry = m_exTimerData.TimerList.Flink;
         pEntry != &m_exTimerData.TimerList;
         pEntry = pEntry->Flink)
    {
        PEX_TIMER pTimer = CONTAINING_RECORD(pEntry, EX_TIMER, AllList);

        if (pTimer->TimerStarted
            && currentTimeUs >= pTimer->TriggerTimeUs
            && (pTimer->Type == ExTimerTypeRelativePeriodic || pTimer->ExpirationCount == 0))
        {
            _ExTimerTrigger(pTimer, currentTimeUs);
        }
    }

    LockRelease(&m_exTimerData.Lock, oldState);
}

STATUS
ExTimerInit(
    OUT     PEX_TIMER       Timer,
    IN      EX_TIMER_TYPE   Type,
    IN      QWORD           Time
    )
{
    STATUS status;
    INTR_STATE oldState;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Type > ExTimerTypeMax)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = STATUS_SUCCESS;

    memzero(Timer, sizeof(EX_TIMER));
    InitializeListHead(&Timer->WaitingList);
    InitializeListHead(&Timer->AllList);

    Timer->Type = Type;
    if (Timer->Type != ExTimerTypeAbsolute)
    {
        // relative time

        // if the time trigger time has already passed the timer will
        // be signaled after the first scheduler tick
        Timer->TriggerTimeUs = IomuGetSystemTimeUs() + Time;
        Timer->ReloadTimeUs = Time;
    }
    else
    {
        // absolute
        Timer->TriggerTimeUs = Time;
    }

    LockAcquire(&m_exTimerData.Lock, &oldState);
    InsertTailList(&m_exTimerData.TimerList, &Timer->AllList);
    LockRelease(&m_exTimerData.Lock, oldState);

    return status;
}

void
ExTimerStart(
    IN      PEX_TIMER       Timer
    )
{
    INTR_STATE oldState;
    QWORD currentTimeUs;

    ASSERT(Timer != NULL);

    LockAcquire(&m_exTimerData.Lock, &oldState);
    if (Timer->TimerUninited)
    {
        LockRelease(&m_exTimerData.Lock, oldState);
        return;
    }

    Timer->TimerStarted = TRUE;
    Timer->TimerStopped = FALSE;
    currentTimeUs = IomuGetSystemTimeUs();
    if (currentTimeUs >= Timer->TriggerTimeUs
        && (Timer->Type == ExTimerTypeRelativePeriodic || Timer->ExpirationCount == 0))
    {
        _ExTimerTrigger(Timer, currentTimeUs);
    }
    LockRelease(&m_exTimerData.Lock, oldState);
}

void
ExTimerStop(
    IN      PEX_TIMER       Timer
    )
{
    INTR_STATE oldState;

    ASSERT(Timer != NULL);

    LockAcquire(&m_exTimerData.Lock, &oldState);
    if (Timer->TimerUninited)
    {
        LockRelease(&m_exTimerData.Lock, oldState);
        return;
    }

    Timer->TimerStarted = FALSE;
    Timer->TimerStopped = TRUE;
    Timer->StopGeneration++;
    _ExTimerWakeWaitingThreads(Timer);
    LockRelease(&m_exTimerData.Lock, oldState);
}

void
ExTimerWait(
    INOUT   PEX_TIMER       Timer
    )
{
    PTHREAD pCurrentThread;
    INTR_STATE oldState;
    INTR_STATE lockState;
    QWORD expirationCount;
    DWORD stopGeneration;

    ASSERT(Timer != NULL);

    pCurrentThread = GetCurrentThread();
    ASSERT(pCurrentThread != NULL);

    oldState = CpuIntrDisable();
    LockAcquire(&m_exTimerData.Lock, &lockState);
    expirationCount = Timer->ExpirationCount;
    stopGeneration = Timer->StopGeneration;

    while (!Timer->TimerUninited
           && !Timer->TimerStopped
           && Timer->StopGeneration == stopGeneration
           && !(Timer->Type != ExTimerTypeRelativePeriodic && Timer->ExpirationCount > 0)
           && !(Timer->Type == ExTimerTypeRelativePeriodic && Timer->ExpirationCount > expirationCount))
    {
        InsertTailList(&Timer->WaitingList, &pCurrentThread->ReadyList);
        ThreadTakeBlockLock();
        LockRelease(&m_exTimerData.Lock, lockState);
        ThreadBlock();
        LockAcquire(&m_exTimerData.Lock, &lockState);
    }

    LockRelease(&m_exTimerData.Lock, lockState);
    CpuIntrSetState(oldState);
}

void
ExTimerUninit(
    INOUT   PEX_TIMER       Timer
    )
{
    INTR_STATE oldState;

    ASSERT(Timer != NULL);

    LockAcquire(&m_exTimerData.Lock, &oldState);
    if (Timer->TimerUninited)
    {
        LockRelease(&m_exTimerData.Lock, oldState);
        return;
    }

    Timer->TimerStarted = FALSE;
    Timer->TimerStopped = TRUE;
    Timer->TimerUninited = TRUE;
    Timer->StopGeneration++;
    RemoveEntryList(&Timer->AllList);
    _ExTimerWakeWaitingThreads(Timer);
    LockRelease(&m_exTimerData.Lock, oldState);
}

INT64
ExTimerCompareTimers(
    IN      PEX_TIMER     FirstElem,
    IN      PEX_TIMER     SecondElem
)
{
    return FirstElem->TriggerTimeUs - SecondElem->TriggerTimeUs;
}