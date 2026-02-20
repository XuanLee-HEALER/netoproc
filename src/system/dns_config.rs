use crate::error::NetopError;

/// Raw DNS resolver configuration
#[derive(Debug, Clone)]
pub struct RawDnsResolver {
    pub interface: String,
    pub server_addresses: Vec<String>,
    pub search_domains: Vec<String>,
}

// ---------------------------------------------------------------------------
// macOS: SystemConfiguration framework
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::ffi::CStr;
    use std::ptr;

    #[allow(non_camel_case_types)]
    type CFTypeRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFStringRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFDictionaryRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFArrayRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFAllocatorRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type CFIndex = isize;
    #[allow(non_camel_case_types)]
    type SCDynamicStoreRef = *const std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type Boolean = u8;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            alloc: CFAllocatorRef,
            c_str: *const libc::c_char,
            encoding: u32,
        ) -> CFStringRef;

        fn CFStringGetCStringPtr(string: CFStringRef, encoding: u32) -> *const libc::c_char;

        fn CFStringGetCString(
            string: CFStringRef,
            buffer: *mut libc::c_char,
            buffer_size: CFIndex,
            encoding: u32,
        ) -> Boolean;

        fn CFArrayGetCount(array: CFArrayRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(array: CFArrayRef, idx: CFIndex) -> CFTypeRef;

        fn CFDictionaryGetValue(dict: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;

        fn CFRelease(cf: CFTypeRef);

        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFDictionaryGetTypeID() -> usize;
    }

    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(
            allocator: CFAllocatorRef,
            name: CFStringRef,
            callout: CFTypeRef,
            context: CFTypeRef,
        ) -> SCDynamicStoreRef;

        fn SCDynamicStoreCopyValue(store: SCDynamicStoreRef, key: CFStringRef) -> CFTypeRef;
    }

    struct CfRef(CFTypeRef);

    impl CfRef {
        fn new(ptr: CFTypeRef) -> Option<Self> {
            if ptr.is_null() { None } else { Some(Self(ptr)) }
        }

        fn as_ptr(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for CfRef {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn cf_string_create(s: &str) -> Option<CfRef> {
        let c_str = std::ffi::CString::new(s).ok()?;
        let cf_str = unsafe {
            CFStringCreateWithCString(ptr::null(), c_str.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };
        CfRef::new(cf_str)
    }

    fn cf_string_to_string(cf_str: CFStringRef) -> Option<String> {
        if cf_str.is_null() {
            return None;
        }

        let type_id = unsafe { CFGetTypeID(cf_str) };
        let string_type_id = unsafe { CFStringGetTypeID() };
        if type_id != string_type_id {
            return None;
        }

        let cptr = unsafe { CFStringGetCStringPtr(cf_str, K_CF_STRING_ENCODING_UTF8) };
        if !cptr.is_null() {
            let cstr = unsafe { CStr::from_ptr(cptr) };
            return Some(cstr.to_string_lossy().into_owned());
        }

        let mut buf = [0u8; 1024];
        let ok = unsafe {
            CFStringGetCString(
                cf_str,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len() as CFIndex,
                K_CF_STRING_ENCODING_UTF8,
            )
        };
        if ok != 0 {
            let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
            Some(cstr.to_string_lossy().into_owned())
        } else {
            None
        }
    }

    fn cf_array_to_strings(array: CFArrayRef) -> Vec<String> {
        if array.is_null() {
            return Vec::new();
        }

        let type_id = unsafe { CFGetTypeID(array) };
        let array_type_id = unsafe { CFArrayGetTypeID() };
        if type_id != array_type_id {
            return Vec::new();
        }

        let count = unsafe { CFArrayGetCount(array) };
        let mut result = Vec::new();

        for i in 0..count {
            let val = unsafe { CFArrayGetValueAtIndex(array, i) };
            if let Some(s) = cf_string_to_string(val) {
                result.push(s);
            }
        }

        result
    }

    fn get_dns_config(store: &CfRef, key: &str) -> Option<(Vec<String>, Vec<String>)> {
        let cf_key = cf_string_create(key)?;

        let value = unsafe { SCDynamicStoreCopyValue(store.as_ptr(), cf_key.as_ptr()) };
        let dict = CfRef::new(value)?;

        let type_id = unsafe { CFGetTypeID(dict.as_ptr()) };
        let dict_type_id = unsafe { CFDictionaryGetTypeID() };
        if type_id != dict_type_id {
            return None;
        }

        let server_key = cf_string_create("ServerAddresses")?;
        let servers_ref = unsafe { CFDictionaryGetValue(dict.as_ptr(), server_key.as_ptr()) };
        let servers = cf_array_to_strings(servers_ref);

        let search_key = cf_string_create("SearchDomains")?;
        let search_ref = unsafe { CFDictionaryGetValue(dict.as_ptr(), search_key.as_ptr()) };
        let search_domains = cf_array_to_strings(search_ref);

        Some((servers, search_domains))
    }

    pub fn list_dns_resolvers() -> Result<Vec<RawDnsResolver>, NetopError> {
        let store_name = cf_string_create("netoproc")
            .ok_or_else(|| NetopError::Fatal("failed to create CFString".to_string()))?;

        let store = unsafe {
            SCDynamicStoreCreate(ptr::null(), store_name.as_ptr(), ptr::null(), ptr::null())
        };

        let store = CfRef::new(store)
            .ok_or_else(|| NetopError::Fatal("failed to create SCDynamicStore".to_string()))?;

        let mut resolvers = Vec::new();

        if let Some(global_dns) = get_dns_config(&store, "State:/Network/Global/DNS") {
            resolvers.push(RawDnsResolver {
                interface: "global".to_string(),
                server_addresses: global_dns.0,
                search_domains: global_dns.1,
            });
        }

        if let Some(setup_dns) = get_dns_config(&store, "Setup:/Network/Global/DNS")
            && !setup_dns.0.is_empty()
        {
            resolvers.push(RawDnsResolver {
                interface: "setup".to_string(),
                server_addresses: setup_dns.0,
                search_domains: setup_dns.1,
            });
        }

        Ok(resolvers)
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::list_dns_resolvers;

// ---------------------------------------------------------------------------
// Linux: parse /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn list_dns_resolvers() -> Result<Vec<RawDnsResolver>, NetopError> {
    parse_resolv_conf("/etc/resolv.conf")
}

/// Parse a resolv.conf-format file into DNS resolver configuration.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_resolv_conf(path: &str) -> Result<Vec<RawDnsResolver>, NetopError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let mut servers = Vec::new();
    let mut search_domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("nameserver") {
            let addr = rest.trim();
            if !addr.is_empty() {
                servers.push(addr.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("domain") {
            let domain = rest.trim();
            if !domain.is_empty() && search_domains.is_empty() {
                search_domains.push(domain.to_string());
            }
        }
    }

    if servers.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![RawDnsResolver {
        interface: "global".to_string(),
        server_addresses: servers,
        search_domains,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolv_conf_basic() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_resolv.conf");
        std::fs::write(
            &path,
            "# Generated by NetworkManager\n\
             nameserver 8.8.8.8\n\
             nameserver 8.8.4.4\n\
             search example.com corp.example.com\n",
        )
        .unwrap();

        let resolvers = parse_resolv_conf(path.to_str().unwrap()).unwrap();
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].server_addresses, vec!["8.8.8.8", "8.8.4.4"]);
        assert_eq!(
            resolvers[0].search_domains,
            vec!["example.com", "corp.example.com"]
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_resolv_conf_empty() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_resolv_empty.conf");
        std::fs::write(&path, "# nothing here\n").unwrap();

        let resolvers = parse_resolv_conf(path.to_str().unwrap()).unwrap();
        assert!(resolvers.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_resolv_conf_missing_file() {
        let resolvers = parse_resolv_conf("/nonexistent/resolv.conf").unwrap();
        assert!(resolvers.is_empty());
    }

    #[test]
    fn parse_resolv_conf_domain_directive() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_resolv_domain.conf");
        std::fs::write(
            &path,
            "nameserver 1.1.1.1\n\
             domain example.org\n",
        )
        .unwrap();

        let resolvers = parse_resolv_conf(path.to_str().unwrap()).unwrap();
        assert_eq!(resolvers[0].search_domains, vec!["example.org"]);

        std::fs::remove_file(&path).ok();
    }
}
