//
//  IMSMemoryManager.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "IMSMemoryManager.h"

static NSPointerArray* unlockedPointers;
static NSPointerArray* lockedPointers;
static NSString* checksumStr;

void initMem(){
    if(!unlockedPointers) {
        NSLog(@"Initializing");
        unlockedPointers =[[NSPointerArray alloc] init];
        lockedPointers = [[NSPointerArray alloc] init];

    }
}

extern inline NSString* hexString(NSObject* obj){
    NSMutableString *hex = [[NSMutableString alloc] init];
    unsigned char* rawObj = (__bridge void*) obj;
    int size = malloc_size((__bridge void*) obj);
    for(int i = 0; i < size; i ++) {
        if(i%15 == 0) [hex appendString:@"\n"];
        [hex appendFormat:@"%02x", rawObj[i]];
    }
    return [NSString stringWithString:hex];
}

extern inline void* getStart(NSObject* obj) {
    if([obj isKindOfClass:[NSString class]]) {
        return ((__bridge void*)obj + 9);
    } else if([obj isKindOfClass:[NSData class]]) {
        return ((__bridge void*)obj + 12);
    } else if([obj isKindOfClass:[NSNumber class]]) {
        return ((__bridge void*)obj + 8);
    } else if([obj isKindOfClass:[NSArray class]]) {
        return ((__bridge void*)obj + 4);
    } else {
        return 0;
    }
}

extern inline int getSize(NSObject* obj) {
    if([obj isKindOfClass:[NSString class]]) {
        return (malloc_size((__bridge void*)obj) - 9);
    } else if([obj isKindOfClass:[NSData class]]) {
        return (malloc_size((__bridge void*)obj) - 12);
    } else if([obj isKindOfClass:[NSNumber class]]) {
        return (malloc_size((__bridge void*)obj) - 8);
    } else if([obj isKindOfClass:[NSArray class]]) {
        return (malloc_size((__bridge void*)obj) - 4);
    } else {
        return 0;
    }
}


// Return yes, if calling function should continue on
// no means caller should return immediately
extern inline BOOL handleType(NSObject* obj, NSString* pass, traversalFunc f) {
    BOOL ret = YES;
    if([obj isKindOfClass:[NSArray class]]){
        ret = NO;
        for( id newObj in (NSArray*)obj) {
            (*f)(newObj, pass);
        }
    }
    NSLog(@"Done with type handler %d", ret);
    return ret;
}

// Wrapper for handling function ptr
extern inline BOOL wipeWrapper(NSObject* obj, NSString* ignore) {
    return wipe(obj);
}

// Return NO if wipe failed
extern inline BOOL wipe(NSObject* obj) {
    NSLog(@"Object pointer: %p", obj);
    if(handleType(obj, @"", &wipeWrapper) == YES) {
        NSLog(@"WIPE OBJ");
        memset( getStart(obj), 0, getSize(obj));
    }
    return YES;
}


// Return NO if object already tracked
extern inline BOOL track(NSObject* obj) {
    initMem();
    [unlockedPointers addPointer:(void *)obj];
    NSLog(@"TRACK %p -- %d", obj, [unlockedPointers count]);
    return YES;
}

extern inline BOOL untrack(NSObject* obj) {
    initMem();
    for(int i = 0; i < [unlockedPointers count]; i ++){
        if([unlockedPointers pointerAtIndex:i] == (__bridge void *)(obj)){
            [unlockedPointers removePointerAtIndex:i];
        }
    }
    
    return YES;
}


// Return count of how many wiped
extern inline int wipeAll() {
    initMem();
    for(id obj in unlockedPointers) wipe(obj);
    
    return [unlockedPointers count];
}

#ifdef iMAS_SecureFoundation
// TODO - obfuscate these
NSString *_saltS = @"12345678";
NSString *_ivS = @"1234567812345678";

extern inline BOOL cryptHelperEncrypt(NSObject* obj, NSString* pass) {
    NSData *salt = [_saltS dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [_ivS dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *key = IMSCryptoUtilsDeriveKey([pass dataUsingEncoding:NSUTF8StringEncoding], kCCKeySizeAES256, salt);
    NSUInteger dataLength = getSize(obj);
    if (!dataLength)
        return NO;
    NSData *plain = [NSData dataWithBytesNoCopy:(void *)(getStart(obj)) length:dataLength];
    NSLog(@"plaintext size is: %zd", [plain length]);
    NSData *ciphertext = IMSCryptoUtilsSimpleEncryptData(plain, key, iv);
    if (!ciphertext)
      return NO;

    //** copy ciphertext over obj
    memcpy(getStart(obj), [ciphertext bytes], dataLength);

    NSLog(@"MovedBytes: %zd -- dataLength: %zd", [ciphertext length], dataLength);

    // TODO: Make sure key is wiped
    // TODO: Return based on cryptStatus 
    return YES;
}

extern inline BOOL cryptHelperDecrypt(NSObject* obj, NSString* pass) {
    NSData *salt = [_saltS dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [_ivS dataUsingEncoding:NSUTF8StringEncoding];

    NSData *key = IMSCryptoUtilsDeriveKey([pass dataUsingEncoding:NSUTF8StringEncoding], kCCKeySizeAES256, salt);
    NSUInteger dataLength = getSize(obj);
    if (!dataLength)
        return NO;
    NSData *ciphertext = [NSData dataWithBytesNoCopy:(void *)(getStart(obj)) length:dataLength];
    NSData *plain = IMSCryptoUtilsSimpleDecryptData(ciphertext, key, iv);
    if (!plain)
      return NO;

    //** copy plaintext over obj
    memcpy(getStart(obj), [plain bytes], dataLength);

    NSLog(@"MovedBytes: %zd -- dataLength: %zd", [plain length], dataLength);

    
    // TODO: Make sure key is wiped
    // TODO: Return based on cryptStatus 
    return YES;
}

#else
//** Apple crypto

// Return YES is the object was encrypted
extern inline BOOL cryptHelper(NSObject* obj, NSString* pass, CCOperation op) {
    NSLog(@"Object pointer: %p", obj);
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [pass getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    size_t bufferSize = getSize(obj) + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    if (!buffer)
        return NO;
    NSUInteger dataLength = getSize(obj);
    if (!dataLength)
        return NO;
        
    size_t movedBytes = 0;
    CCCryptorStatus cryptStatus = CCCrypt(op,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES128,
                                          NULL,
                                          getStart(obj),
                                          dataLength,
                                          buffer, bufferSize,
                                          &movedBytes);
    memcpy(getStart(obj), buffer, dataLength);
    free(buffer);
    NSLog(@"MovedBytes: %zd -- dataLength: %zd -- bufferSize: %zd", movedBytes, dataLength, bufferSize);
    // TODO: Make sure key is wiped
    // TODO: Return based on cryptStatus 
    if (cryptStatus == kCCSuccess){
        NSLog(@"SUCCESS");
    } else if(cryptStatus == kCCDecodeError) {
        NSLog(@"DECODE ERROR");
        return NO;
    } else if(cryptStatus == kCCBufferTooSmall) {
        NSLog(@"BUFFER SIZE ERROR");
        return NO;
    } else {
        NSLog(@"OTHER ERROR");
        return NO;
    }
    return YES;
}

//** end #ifdef iMAS_SecureFoundation
#endif



extern inline BOOL lock(NSObject* obj, NSString* pass) {
    if(handleType(obj, @"", &lock) == YES) {
#ifdef iMAS_SecureFoundation
      return cryptHelperEncrypt(obj, pass);
#else
      return cryptHelper(obj, pass, kCCEncrypt);
#endif
    } else
      return YES;
}

extern inline BOOL unlock(NSObject* obj, NSString* pass) {
   if(handleType(obj, @"", &unlock) == YES) {
#ifdef iMAS_SecureFoundation
     return cryptHelperDecrypt(obj, pass);
#else
     return cryptHelper(obj, pass, kCCDecrypt);
#endif
    } else
     return YES;
}



extern inline BOOL lockAll(NSString* pass) {
    initMem();
    for(id obj in unlockedPointers) {
        lock(obj, pass);
        [lockedPointers addPointer:(void *)obj];
    }
    
    return YES;
}

extern inline BOOL unlockAll(NSString* pass) {
    initMem();
    for(id obj in lockedPointers) {
        unlock(obj, pass);
    }
    for(int i = 0; i < [lockedPointers count]; i ++) {
       [lockedPointers removePointerAtIndex:i];
    }
    return YES;
}

extern inline BOOL checksumTest() {
    initMem();
    NSString* checksumTmp = [checksumStr copy];
    NSString* newSum = checksumMemHelper(NO);
    
    if([checksumTmp isEqualToString:newSum]) return YES;
    else return NO;
}

extern inline NSString* checksumObj(NSObject* obj) {
    NSLog(@"Object pointer: %p", obj);
    NSMutableString *hex = [[NSMutableString alloc] init];

#ifdef iMAS_SecureFoundation
    unsigned char* digest = malloc(SHA256_DIGEST_LENGTH);
    digest = IMSHashBytes_SHA256((__bridge void*)obj, malloc_size((__bridge void*)obj));

   if (digest) {
      for (NSUInteger i=0; i < SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    }
    free(digest);
    return [NSString stringWithString:hex];
#else

    
    unsigned char* digest = malloc(CC_SHA1_DIGEST_LENGTH);
    if (CC_SHA1((__bridge void*)obj, malloc_size((__bridge void*)obj), digest)) {
        for (NSUInteger i=0; i<CC_SHA1_DIGEST_LENGTH; i++)
            [hex appendFormat:@"%02x", digest[i]];
    }
    free(digest);
    return [NSString stringWithString:hex];
#endif    

}

extern inline NSString* checksumMemHelper(BOOL saveStr) {
    initMem();
    NSMutableString *hex = [[NSMutableString alloc] init];
    
    for(id obj in unlockedPointers) {
        [hex appendFormat:@"%p", obj];
        [hex appendString:checksumObj(obj)];
    }
    if(saveStr) {
        checksumStr = [NSString stringWithString:hex];
        return [checksumStr copy];
    } else {
        return [NSString stringWithString:hex];
    }
}

extern inline NSString* checksumMem() {
    return checksumMemHelper(YES);
}
