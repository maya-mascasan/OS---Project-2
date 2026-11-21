#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "thread.h"
#include "thread_internal.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "cal_annotate.h"
#include "cal_assembly.h"
#include "cal_seh.h"
#include "vmm.h"
#include "ex.h"
#include "io.h"
#include "iomu.h"
#include "cpumu.h"

extern void MS_ABI SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

typedef enum {
    UmHandleTypeProcess = 1,
    UmHandleTypeThread,
    UmHandleTypeFile
} UM_HANDLE_TYPE;

typedef struct UM_HANDLE_ENTRY {
    LIST_ENTRY ListEntry;
    UM_HANDLE HandleValue;
    UM_HANDLE_TYPE HandleType;
    PVOID KernelObject; 
} UM_HANDLE_ENTRY;

STATUS UmHandleAdd(PPROCESS process, UM_HANDLE_TYPE type, PVOID object, UM_HANDLE* OutHandle) {
    UM_HANDLE_ENTRY *new = (UM_HANDLE_ENTRY*)ExAllocatePoolWithTag(0, sizeof(UM_HANDLE_ENTRY), 'hdle', 0);
    if (!new)
    {
        return STATUS_HEAP_NO_MORE_MEMORY;
    }

    MutexAcquire(&process->HandleTableLock);
    
    UM_HANDLE id = process->NextHandleValue++;
    new->HandleValue = id;
    new->HandleType = type;
    new->KernelObject = object;
    InsertTailList(&process->HandleTableList, &new->ListEntry);
    
    MutexRelease(&process->HandleTableLock);
    
    *OutHandle = id;
    
    return STATUS_SUCCESS;
}

STATUS UmHandleGet(PPROCESS process, UM_HANDLE value, UM_HANDLE_TYPE expectedType, PVOID* object) {
    STATUS status = STATUS_INVALID_PARAMETER1;
    PLIST_ENTRY current;
    UM_HANDLE_ENTRY *entry;

    MutexAcquire(&process->HandleTableLock);
    
    current = process->HandleTableList.Flink;           
    while (current != &process->HandleTableList) {     
        entry = CONTAINING_RECORD(current, UM_HANDLE_ENTRY, ListEntry);

        if (entry->HandleValue == value) {
            if (entry->HandleType == expectedType) {
                *object = entry->KernelObject;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER1;
            }
            break;
        }

        current = current->Flink;                        
    }
    
    MutexRelease(&process->HandleTableLock);
    return status;
}

STATUS UmHandleRemove(PPROCESS process, UM_HANDLE value, UM_HANDLE_TYPE expectedType, PVOID* object) {
    STATUS status = STATUS_INVALID_PARAMETER1;
    PLIST_ENTRY current;
    UM_HANDLE_ENTRY *entry;

    MutexAcquire(&process->HandleTableLock);

    current = process->HandleTableList.Flink;     
    while (current != &process->HandleTableList) {     
        entry = CONTAINING_RECORD(current, UM_HANDLE_ENTRY, ListEntry);

        if (entry->HandleValue == value) {
            if (entry->HandleType == expectedType) {
                *object = entry->KernelObject;
                RemoveEntryList(current);
                ExFreePoolWithTag(entry, 'hdle');
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER1;
            }
            break;
        }

        current = current->Flink;                        
    }
    
    MutexRelease(&process->HandleTableLock);
    return status;
}

void
MS_ABI
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    QWORD parameterBufferSize;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        parameterBufferSize = SHADOW_STACK_SIZE;
        switch (sysCallId)
        {
        case SyscallIdProcessCreate:
        case SyscallIdFileCreate:
            parameterBufferSize = 6 * sizeof(QWORD);
            break;
        case SyscallIdFileWrite:
        case SyscallIdFileRead:
            parameterBufferSize = 5 * sizeof(QWORD);
            break;
        case SyscallIdProcessGetPid:
        case SyscallIdProcessWaitForTermination:
        case SyscallIdThreadGetTid:
        case SyscallIdThreadWaitForTermination:
            parameterBufferSize = 3 * sizeof(QWORD);
            break;
        case SyscallIdThreadCreate:
            parameterBufferSize = 4 * sizeof(QWORD);
            break;
        default:
            break;
        }

        status = MmuIsBufferValid(pParameters, parameterBufferSize, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
          case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
            );
            break;
        // STUDENT TODO: implement the rest of the syscalls 
        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid(
                (UM_HANDLE)pSyscallParameters[0],
                (PID*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdProcessWaitForTermination:
            status = SyscallProcessWaitForTermination(
                (UM_HANDLE)pSyscallParameters[0],
                (STATUS*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessCloseHandle:
            status = SyscallProcessCloseHandle(
                (UM_HANDLE)pSyscallParameters[0]
            );
            break;
        case SyscallIdFileClose:
            status = SyscallFileClose((UM_HANDLE)pSyscallParameters[0]);
            break;
        case SyscallIdFileCreate:
            status = SyscallFileCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (BOOLEAN)pSyscallParameters[2],
                (BOOLEAN)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdFileRead:
            status = SyscallFileRead(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
            );
            break;
        case SyscallIdThreadCreate:
            status = SyscallThreadCreate(
                (PFUNC_ThreadStart)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (UM_HANDLE*)pSyscallParameters[2]
            );
            break;
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid(
                (UM_HANDLE)pSyscallParameters[0],
                (TID*)pSyscallParameters[1]
            );
            break;
        case SyscallIdThreadWaitForTermination:
            status = SyscallThreadWaitForTermination(
                (UM_HANDLE)pSyscallParameters[0],
                (STATUS*)pSyscallParameters[1]
            );
            break;
        case SyscallIdThreadCloseHandle:
            status = SyscallThreadCloseHandle(
                (UM_HANDLE)pSyscallParameters[0]
            );
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    AsmWriteMsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    AsmWriteMsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    AsmWriteMsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS Process;
    Process = GetCurrentProcess();
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    PPROCESS process = GetCurrentProcess();
    STATUS status;

    status = MmuIsBufferValid(BytesWritten, sizeof(QWORD), PAGE_RIGHTS_WRITE, process);
    if (!SUCCEEDED(status))
    {
        return STATUS_INVALID_PARAMETER4;
    }

    if (BytesToWrite != 0)
    {
        status = MmuIsBufferValid(Buffer, BytesToWrite, PAGE_RIGHTS_READ, process);
        if (!SUCCEEDED(status))
        {
            return STATUS_INVALID_PARAMETER2;
        }
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        *BytesWritten = BytesToWrite;
        if (GetCurrentProcess()->StdoutClosed)
            return STATUS_SUCCESS;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;
    }

    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID*                    ProcessId
)
{
    PPROCESS process = GetCurrentProcess();
    PPROCESS target = NULL; 
    STATUS status;

    status = MmuIsBufferValid(ProcessId, sizeof(PID), PAGE_RIGHTS_WRITE, process); 
    if (ProcessId == NULL || !SUCCEEDED(status))
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = UmHandleGet(process, ProcessHandle, UmHandleTypeProcess, (PVOID*)&target);
    if (ProcessHandle != UM_INVALID_HANDLE_VALUE && !SUCCEEDED(status))
    {
        return STATUS_INVALID_PARAMETER1;
    }

    *ProcessId = ProcessGetId(target);
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
                char*               ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
                char*               Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE*          ProcessHandle
)
{
    STATUS status;
    PPROCESS process = GetCurrentProcess();
    char* fullPath = NULL;
    QWORD pathSize;
    BOOLEAN ok = FALSE; // ok = true for absolute path

    if (ProcessPath == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (PathLength == 0 || PathLength > MAX_PATH)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    if (ProcessHandle == NULL)
    {
        return STATUS_INVALID_PARAMETER5;
    }

    status = MmuIsBufferValid((PVOID)ProcessHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, process); 
    if (!SUCCEEDED(status)) 
    {
        return STATUS_INVALID_PARAMETER5;
    }

    status = MmuIsBufferValid((PVOID)ProcessPath, PathLength, PAGE_RIGHTS_READ, process); 
    if (!SUCCEEDED(status)) 
    {
        return STATUS_INVALID_PARAMETER1;
    }

    for (pathSize = 0; pathSize < PathLength && ProcessPath[pathSize] != '\0'; pathSize++)
    {
    }
    if (pathSize == 0 || pathSize == PathLength)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Arguments != NULL)
    {
        QWORD argumentIndex;

        if (ArgLength == 0 || ArgLength > STACK_DEFAULT_SIZE)
        {
            return STATUS_INVALID_PARAMETER3;
        }

        status = MmuIsBufferValid((PVOID)Arguments, ArgLength, PAGE_RIGHTS_READ, process); 
        if (!SUCCEEDED(status)) 
        {
            return STATUS_INVALID_PARAMETER3;
        }

        for (argumentIndex = 0;
             argumentIndex < ArgLength && Arguments[argumentIndex] != '\0';
             argumentIndex++)
        {
        }
        if (argumentIndex == ArgLength)
        {
            return STATUS_INVALID_PARAMETER3;
        }
    }
    else if (ArgLength != 0)
    {
        return STATUS_INVALID_PARAMETER4;
    }

    //if absolute path "D:\Sample.exe"
    if (pathSize >= 3 && ProcessPath[1] == ':' && ProcessPath[2] == '\\')
    {
        ok = TRUE;
    }

    if (ok)
    {
        fullPath = (char*)ProcessPath;
    }
    else
    {
        // relative path 
        const char* drive = IomuGetSystemPartitionPath();
        const char* dir = "Applications\\";
        
        QWORD lenSystem = 0;
        while (drive[lenSystem] != '\0') lenSystem++;
        
        QWORD lenApp = 0;
        while (dir[lenApp] != '\0') lenApp++;
        
        QWORD totalLen = lenSystem + lenApp + pathSize + 1;
        
        fullPath = (char*)ExAllocatePoolWithTag(0, totalLen, 'path', 0);
        if (fullPath == NULL)
        {
            return STATUS_HEAP_NO_MORE_MEMORY;
        }

        QWORD offset = 0;
        for (QWORD i = 0; i < lenSystem; i++) 
            fullPath[offset++] = drive[i];
        for (QWORD i = 0; i < lenApp; i++) 
            fullPath[offset++] = dir[i];
        for (QWORD i = 0; i < pathSize; i++)
            fullPath[offset++] = ProcessPath[i];
        fullPath[offset] = '\0';
    }

    PPROCESS newProcess = NULL;
    status = ProcessCreate(fullPath, Arguments, &newProcess);

    if (fullPath != ProcessPath)
    {
        ExFreePoolWithTag(fullPath, 'path');
    }

    if (!SUCCEEDED(status)) 
    {
        return status;
    }

    status = UmHandleAdd(process, UmHandleTypeProcess, newProcess, ProcessHandle);

    return status;
}

STATUS
SyscallProcessWaitForTermination(
    IN  UM_HANDLE               ProcessHandle,
    OUT STATUS*                 TerminationStatus
)
{
    STATUS status;
    STATUS exitStatus;
    PPROCESS target = NULL;
    PPROCESS process = GetCurrentProcess();
    
    status = UmHandleGet(process, ProcessHandle, UmHandleTypeProcess, (PVOID*)&target);
    if (!SUCCEEDED(status)) 
    {
        return status;
    }
    
    if (TerminationStatus != NULL)
    {
        status = MmuIsBufferValid((PVOID)TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_WRITE, process);
        if (!SUCCEEDED(status)) 
        {
            return STATUS_INVALID_PARAMETER2;
        }
    }
    
    ProcessWaitForTermination(target, &exitStatus);
    
    if (TerminationStatus != NULL)
    {
        *TerminationStatus = exitStatus;
    }
    
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCloseHandle(
    IN  UM_HANDLE               ProcessHandle
)
{
    PPROCESS target = NULL;
    PPROCESS process = GetCurrentProcess();
    
    STATUS status = UmHandleRemove(process, ProcessHandle, UmHandleTypeProcess, (PVOID*)&target);
    if (!SUCCEEDED(status)) 
    {
        return status;
    }
    
    ProcessCloseHandle(target);
    
    return STATUS_SUCCESS;
}

STATUS
SyscallFileClose(
    IN UM_HANDLE FileHandle
)
{
    PFILE_OBJECT pFile = NULL;
    PPROCESS currentProcess = GetCurrentProcess();
    STATUS status;
    if (FileHandle == UM_FILE_HANDLE_STDOUT)
    {
        status = STATUS_SUCCESS;
        MutexAcquire(&currentProcess->HandleTableLock);
        if (currentProcess->StdoutClosed)
            status = STATUS_INVALID_PARAMETER1;
        else
            currentProcess->StdoutClosed = TRUE;
        MutexRelease(&currentProcess->HandleTableLock);
        return status;
    }
    status = UmHandleRemove(currentProcess, FileHandle, UmHandleTypeFile, (PVOID*)&pFile);
    if (!SUCCEEDED(status)) 
        return status;
    return IoCloseFile(pFile);
}

STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength) char* Path,
    IN QWORD PathLength,
    IN BOOLEAN Directory,
    IN BOOLEAN Create,
    OUT UM_HANDLE* FileHandle
)
{
    STATUS status;
    PPROCESS currentProcess = GetCurrentProcess();
    PFILE_OBJECT pFile = NULL;
    const char* prefix = "";
    QWORD prefixLen = 0;
    QWORD pathLen = 0;
    QWORD offset = 0;
    char* fullPath = NULL;
    if (PathLength > MAX_PATH)
        return STATUS_INVALID_PARAMETER1;
    status = MmuIsBufferValid((PVOID)FileHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER5;
    status = MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_READ, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER1;
    while (pathLen < PathLength && Path[pathLen] != '\0') 
        pathLen++;
    if (pathLen == 0)
        return STATUS_INVALID_PARAMETER1;
    if (!(pathLen >= 3 && Path[1] == ':' && Path[2] == '\\'))
    {
        prefix = IomuGetSystemPartitionPath();
        while (prefix[prefixLen] != '\0') prefixLen++;
    }
    fullPath = (char*)ExAllocatePoolWithTag(PoolAllocateZeroMemory, (DWORD)(prefixLen + pathLen + 1), 'eliF', 0);
    if (fullPath == NULL) 
        return STATUS_HEAP_NO_MORE_MEMORY;
    for (QWORD i = 0; i < prefixLen; i++) 
        fullPath[offset++] = prefix[i];
    for (QWORD i = 0; i < pathLen; i++) 
        fullPath[offset++] = Path[i];
    fullPath[offset] = '\0';
    status = IoCreateFile(&pFile, fullPath, Directory, Create, FALSE);
    ExFreePoolWithTag(fullPath, 'eliF');
    if (!SUCCEEDED(status)) 
        return status;
    status = UmHandleAdd(currentProcess, UmHandleTypeFile, pFile, FileHandle);
    if (!SUCCEEDED(status))
    {
        IoCloseFile(pFile);
        return status;
    }
    return STATUS_SUCCESS;
}

STATUS
SyscallFileRead(
    IN UM_HANDLE FileHandle,
    OUT_WRITES_BYTES(BytesToRead) PVOID Buffer,
    IN QWORD BytesToRead,
    OUT QWORD* BytesRead
)
{
    STATUS status;
    PPROCESS currentProcess = GetCurrentProcess();
    PFILE_OBJECT pFile = NULL;
    QWORD bytesRead = 0;
    status = MmuIsBufferValid((PVOID)BytesRead, sizeof(QWORD), PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status))
        return STATUS_INVALID_PARAMETER4;
    status = UmHandleGet(currentProcess, FileHandle, UmHandleTypeFile, (PVOID*)&pFile);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER1;
    if (BytesToRead == 0)
    {
        *BytesRead = 0;
        return STATUS_SUCCESS;
    }
    status = MmuIsBufferValid(Buffer, BytesToRead, PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER2;
    status = IoReadFile(pFile, BytesToRead, NULL, Buffer, &bytesRead);
    if (!SUCCEEDED(status)) 
        return status;
    *BytesRead = bytesRead;
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadCreate(
    IN PFUNC_ThreadStart StartFunction,
    IN_OPT PVOID Context,
    OUT UM_HANDLE* ThreadHandle
)
{
    STATUS status;
    PPROCESS currentProcess = GetCurrentProcess();
    PTHREAD pThread = NULL;
    status = MmuIsBufferValid((PVOID)ThreadHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER3;
    status = MmuIsBufferValid((PVOID)StartFunction, sizeof(BYTE), PAGE_RIGHTS_EXECUTE, currentProcess);
    if (!SUCCEEDED(status))
        return STATUS_INVALID_PARAMETER1;
    status = ThreadCreateEx("UmThread", ThreadPriorityDefault, StartFunction, Context, &pThread, currentProcess);
    if (!SUCCEEDED(status)) 
        return status;
    status = UmHandleAdd(currentProcess, UmHandleTypeThread, pThread, ThreadHandle);
    if (!SUCCEEDED(status))
    {
        ThreadCloseHandle(pThread);
        return status;
    }
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT UM_HANDLE ThreadHandle,
    OUT TID* ThreadId
)
{
    STATUS status;
    PPROCESS currentProcess = GetCurrentProcess();
    PTHREAD pThread = NULL;
    status = MmuIsBufferValid((PVOID)ThreadId, sizeof(TID), PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER2;
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE)
    {
        *ThreadId = ThreadGetId(NULL);
        return STATUS_SUCCESS;
    }
    status = UmHandleGet(currentProcess, ThreadHandle, UmHandleTypeThread, (PVOID*)&pThread);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER1;
    *ThreadId = ThreadGetId(pThread);
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadWaitForTermination(
    IN UM_HANDLE ThreadHandle,
    OUT STATUS* TerminationStatus
)
{
    STATUS status;
    STATUS exitStatus;
    PPROCESS currentProcess = GetCurrentProcess();
    PTHREAD pThread = NULL;
    status = MmuIsBufferValid((PVOID)TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER2;
    status = UmHandleGet(currentProcess, ThreadHandle, UmHandleTypeThread, (PVOID*)&pThread);
    if (!SUCCEEDED(status)) 
        return STATUS_INVALID_PARAMETER1;
    ThreadWaitForTermination(pThread, &exitStatus);
    *TerminationStatus = exitStatus;
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadCloseHandle(
    IN UM_HANDLE ThreadHandle
)
{
    PTHREAD pThread = NULL;
    STATUS status = UmHandleRemove(GetCurrentProcess(), ThreadHandle, UmHandleTypeThread, (PVOID*)&pThread);
    if (!SUCCEEDED(status)) 
        return status;
    ThreadCloseHandle(pThread);
    return STATUS_SUCCESS;
}