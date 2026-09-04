use std::{ffi::c_void, io, mem::size_of, ptr};

use tokio::process::Child;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
        Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
    },
};

/// Owns an unnamed Windows Job Object for one process tree.
///
/// The caller must create `child` with `CREATE_SUSPENDED`. Construction assigns
/// that suspended process to a kill-on-close Job before resuming its primary
/// thread, so no descendant can escape the Job between spawn and assignment.
#[derive(Debug)]
pub struct WindowsProcessTree {
    job: OwnedKernelHandle,
}

#[derive(Debug)]
struct OwnedKernelHandle(HANDLE);

// Windows kernel handles may be closed or used from any process thread. This
// wrapper owns exactly one handle and never aliases mutable Rust data.
unsafe impl Send for OwnedKernelHandle {}

impl OwnedKernelHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper is the sole owner of the live kernel handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

impl WindowsProcessTree {
    pub fn new(child: &Child) -> io::Result<Self> {
        // SAFETY: null security attributes and name request an unnamed Job
        // Object with default security; the returned handle is checked.
        let job = OwnedKernelHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` has the exact structure and byte length required by
        // JobObjectExtendedLimitInformation and remains alive for the call.
        let configured = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        let process_id = child.id().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "child process ID is unavailable")
        })?;
        let process = child.raw_handle().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "child process handle is unavailable",
            )
        })? as HANDLE;
        // SAFETY: both handles are live kernel handles owned by this process;
        // the child was created suspended and cannot start descendants yet.
        if unsafe { AssignProcessToJobObject(job.raw(), process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        resume_primary_thread(process_id)?;
        Ok(Self { job })
    }

    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: `self.job` remains owned and live for this call.
        if unsafe { TerminateJobObject(self.job.raw(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn resume_primary_thread(process_id: u32) -> io::Result<()> {
    // SAFETY: the snapshot call has no borrowed pointer inputs; its returned
    // handle is validated and owned by `snapshot`.
    let snapshot =
        OwnedKernelHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: `entry` is correctly sized, initialized, and exclusively borrowed
    // for the duration of the ToolHelp call.
    let mut found = unsafe { Thread32First(snapshot.raw(), &mut entry) } != 0;
    while found {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: the thread ID came from a live ToolHelp snapshot and only
            // the suspend/resume permission is requested.
            let thread = OwnedKernelHandle::new(unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID)
            })?;
            // SAFETY: `thread` is a live thread handle with resume access.
            let previous_suspend_count = unsafe { ResumeThread(thread.raw()) };
            if previous_suspend_count == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous_suspend_count != 1 {
                return Err(io::Error::other(
                    "child primary thread had an unexpected suspend count",
                ));
            }
            return Ok(());
        }
        // SAFETY: same initialized exclusive output pointer as Thread32First.
        found = unsafe { Thread32Next(snapshot.raw(), &mut entry) } != 0;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "child primary thread was not found",
    ))
}
