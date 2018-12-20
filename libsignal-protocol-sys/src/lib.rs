#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_sys as openssl;
    use std::{mem, os::raw::*, ptr};

    unsafe fn create_test_ec_public_key(
        context: *mut signal_context,
    ) -> *mut ec_public_key {
        let result;
        let mut key_pair: *mut ec_key_pair = ptr::null_mut();
        result = curve_generate_key_pair(context, &mut key_pair);
        assert_eq!(result, 0);
        ec_key_pair_get_public(key_pair)
    }

    unsafe extern "C" fn logger(
        level: ::std::os::raw::c_int,
        message: *const ::std::os::raw::c_char,
        _: usize,
        _: *mut ::std::os::raw::c_void,
    ) {
        println!("Level {}: {}", level, *message);
    }

    unsafe extern "C" fn random_generator(
        data: *mut u8,
        len: usize,
        _: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int {
        if openssl::RAND_bytes(data, len as i32) == 1 {
            0
        } else {
            println!("OpenSSL Error: {}", openssl::ERR_get_error());
            SG_ERR_UNKNOWN
        }
    }

    unsafe extern "C" fn hmac_sha256_init(
        hmac_context: *mut *mut std::ffi::c_void,
        key: *const u8,
        key_len: usize,
        _: *mut std::ffi::c_void,
    ) -> i32 {
        let ctx = openssl::HMAC_CTX_new();
        if ctx.is_null() {
            SG_ERR_NOMEM
        } else {
            *hmac_context = ctx as *mut c_void;
            if openssl::HMAC_Init_ex(
                ctx,
                key as *const c_void,
                key_len as i32,
                openssl::EVP_sha256(),
                ptr::null_mut() as *mut _,
            ) != 1
            {
                return SG_ERR_UNKNOWN;
            }
            0
        }
    }

    unsafe extern "C" fn hmac_sha256_update(
        hmac_context: *mut std::ffi::c_void,
        data: *const u8,
        data_len: usize,
        _: *mut std::ffi::c_void,
    ) -> i32 {
        let ctx = hmac_context as *mut openssl::HMAC_CTX;
        let result = openssl::HMAC_Update(ctx, data, data_len);
        if result == 1 {
            0
        } else {
            -1
        }
    }

    unsafe extern "C" fn hmac_sha256_final(
        hmac_context: *mut std::ffi::c_void,
        output: *mut *mut signal_buffer,
        _: *mut std::ffi::c_void,
    ) -> i32 {
        let md: [c_uchar; openssl::EVP_MAX_MD_SIZE as usize] =
            [0; openssl::EVP_MAX_MD_SIZE as usize];
        let mut len = 0;
        let ctx = hmac_context as *mut openssl::HMAC_CTX;
        if openssl::HMAC_Final(ctx, md.as_ptr() as *mut u8, &mut len) != 1 {
            return SG_ERR_UNKNOWN;
        }
        let output_buffer =
            signal_buffer_create(md.as_ptr() as *mut u8, len as usize);
        if output_buffer.is_null() {
            SG_ERR_NOMEM
        } else {
            *output = output_buffer;
            0
        }
    }

    unsafe extern "C" fn hmac_sha256_cleanup(
        hmac_context: *mut std::ffi::c_void,
        _: *mut std::ffi::c_void,
    ) {
        if !hmac_context.is_null() {
            let ctx = hmac_context as *mut openssl::HMAC_CTX;
            openssl::HMAC_CTX_free(ctx);
        }
    }

    unsafe fn create_signal_context() -> *mut signal_context {
        let null_void: *mut c_void = ptr::null_mut();
        let mut global_context: *mut signal_context = ptr::null_mut();
        let result = signal_context_create(&mut global_context, null_void);
        assert_eq!(result, 0);
        signal_context_set_log_function(global_context, Some(logger));

        let crypto_provider = signal_crypto_provider {
            random_func: Some(random_generator),
            hmac_sha256_init_func: Some(hmac_sha256_init),
            hmac_sha256_update_func: Some(hmac_sha256_update),
            hmac_sha256_final_func: Some(hmac_sha256_final),
            hmac_sha256_cleanup_func: Some(hmac_sha256_cleanup),
            sha512_digest_init_func: None,
            sha512_digest_update_func: None,
            sha512_digest_final_func: None,
            sha512_digest_cleanup_func: None,
            encrypt_func: None,
            decrypt_func: None,
            user_data: null_void,
        };
        let result = signal_context_set_crypto_provider(
            global_context,
            &crypto_provider,
        );
        assert_ne!(result, SG_ERR_INVAL);
        global_context
    }

    unsafe fn compare_signal_messages(
        message1: *mut signal_message,
        message2: *mut signal_message,
    ) {
        let sender_ratchet_key1 =
            signal_message_get_sender_ratchet_key(message1);
        let sender_ratchet_key2 =
            signal_message_get_sender_ratchet_key(message2);
        assert_eq!(
            ec_public_key_compare(sender_ratchet_key1, sender_ratchet_key2),
            0
        );
        let version1 = signal_message_get_message_version(message1);
        let version2 = signal_message_get_message_version(message2);
        assert_eq!(version1, version2);
        let counter1 = signal_message_get_counter(message1);
        let counter2 = signal_message_get_counter(message2);
        assert_eq!(counter1, counter2);

        let body1 = signal_message_get_body(message1);
        let body2 = signal_message_get_body(message2);
        assert_eq!(signal_buffer_compare(body1, body2), 0);
    }

    #[test]
    fn should_serialize_signal_message() {
        unsafe {
            let mut result;
            let context = create_signal_context();
            let ciphertext = "WhisperCipherText";
            let sender_ratchet_key = create_test_ec_public_key(context);
            let sender_identity_key = create_test_ec_public_key(context);
            let receiver_identity_key = create_test_ec_public_key(context);
            const mac_key: [u8; RATCHET_MAC_KEY_LENGTH as usize] =
                [1; RATCHET_MAC_KEY_LENGTH as usize];
            let mut message: *mut signal_message = ptr::null_mut();
            let mut result_message: *mut signal_message = ptr::null_mut();
            result = signal_message_create(
                &mut message,
                3,
                mac_key.as_ptr() as *const u8,
                mem::size_of_val(&mac_key),
                sender_ratchet_key,
                2, // counter
                1, // previous counter
                ciphertext.as_ptr() as *const u8,
                mem::size_of_val(ciphertext) - 1,
                sender_identity_key,
                receiver_identity_key,
                context,
            );
            assert_eq!(result, 0);
            let serialized = ciphertext_message_get_serialized(
                message as *const ciphertext_message,
            );
            assert!(!serialized.is_null());
            result = signal_message_deserialize(
                &mut result_message,
                signal_buffer_data(serialized),
                signal_buffer_len(serialized),
                context,
            );
            assert_eq!(result, 0);
            compare_signal_messages(message, result_message);
            // Exercise the MAC verification code
            result = signal_message_verify_mac(
                result_message,
                sender_identity_key,
                receiver_identity_key,
                mac_key.as_ptr() as *const u8,
                mem::size_of_val(&mac_key),
                context,
            );
            assert_eq!(result, 1);
        }
    }
}
