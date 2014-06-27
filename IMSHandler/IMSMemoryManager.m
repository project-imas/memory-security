//
//  IMSMemoryManager.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "IMSMemoryManager.h"

const size_t OFFSET_SSTRING = 9;
const size_t OFFSET_LSTRING = 12;
const size_t OFFSET_NUMBER  = 8;
const size_t OFFSET_ARRAY   = 8;

const size_t OFFSET_7DATA    = 8;        // iOS >= 7.0
const size_t OFFSET_6DATA    = 16;       // iOS <= 6.1

static NSPointerArray* unlockedPointers;
static NSPointerArray* lockedPointers;
static NSString* checksumStr;
static NSMutableDictionary *ivtable;

void initMem(){
    if(!unlockedPointers) {
        NSLog(@"Initializing");
        unlockedPointers =[[NSPointerArray alloc] init];
        lockedPointers = [[NSPointerArray alloc] init];
    }
    
//    iv_data = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
}

inline NSString* hexString(NSObject* obj){
    NSMutableString *hex = [[NSMutableString alloc] init];
    unsigned char* rawObj = (__bridge void*) obj;
    int size = malloc_size((__bridge void*) obj);
    for(int i = 0; i < size; i ++) {
        if(i%32==0 && i != 0) [hex appendString:@"\n"];
        else if(i%4==0 && i != 0) [hex appendString:@" "];
        [hex appendFormat:@"%02X", rawObj[i]];
    }
    return [NSString stringWithString:hex];
}

inline void* getStart(NSObject* obj) {
    
    float iosversion = [[[UIDevice currentDevice] systemVersion] floatValue];
    
    if([obj isKindOfClass:[NSString class]]) {
        if([(NSString*)obj length] < 256)
            return ((__bridge void*)obj + OFFSET_SSTRING);
        else
            return ((__bridge void*)obj + OFFSET_LSTRING);
    } else if([obj isKindOfClass:[NSData class]]) {
        return ((__bridge void*)obj + ((iosversion < 7.0)?OFFSET_6DATA:OFFSET_7DATA));
    } else if([obj isKindOfClass:[NSNumber class]]) {
        return ((__bridge void*)obj + OFFSET_NUMBER);
    } else if([obj isKindOfClass:[NSArray class]]) {
        return ((__bridge void*)obj + OFFSET_ARRAY);
    } else {
        return 0;
    }
}

inline int getSize(NSObject* obj) {
    
    float iosversion = [[[UIDevice currentDevice] systemVersion] floatValue];
    
    if([obj isKindOfClass:[NSString class]]) {
        if ([(NSString *)obj length] < 256)
            return (malloc_size((__bridge void*)obj) - OFFSET_SSTRING);
        else
            return (malloc_size((__bridge void*)obj) - OFFSET_LSTRING);
    } else if([obj isKindOfClass:[NSData class]]) {
        return (malloc_size((__bridge void*)obj) - ((iosversion < 7.0)?OFFSET_6DATA:OFFSET_7DATA));
    } else if([obj isKindOfClass:[NSNumber class]]) {
        return (malloc_size((__bridge void*)obj) - OFFSET_NUMBER);
    } else if([obj isKindOfClass:[NSArray class]]) {
        return (malloc_size((__bridge void*)obj) - OFFSET_ARRAY);
    } else {
        return 0;
    }
}

inline NSString* getKey(void* obj) {
    return [NSString stringWithFormat:@"%p",obj];
}

// Return yes, if calling function should continue on
// no means caller should return immediately
inline BOOL handleType(NSObject* obj, NSString* pass, traversalFunc f) {
    BOOL ret = YES;
    if([obj isKindOfClass:[NSArray class]]){
        ret = NO;
        for(id newObj in (NSArray*)obj) {
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

// Return YES if the object was encrypted
extern inline BOOL cryptHelper(NSObject* obj, NSString* pass, CCOperation op) {
    BOOL success = NO;
    CCCryptorStatus cryptorStatus;
    
    NSLog(@"Object pointer: %p", obj);
    char *keyPtr = malloc(kCCKeySizeAES256+1);
    bzero(keyPtr, kCCKeySizeAES256+1);
    [pass getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    cryptorStatus = cryptwork(op, getStart(obj), getSize(obj), keyPtr, kCCKeySizeAES256);
    
    switch(cryptorStatus){
        case kCCSuccess:        NSLog(@"SUCCESS");              success = YES;      break;
        case kCCParamError:     NSLog(@"ERR: PARAMETER ERROR");                     break;
        case kCCBufferTooSmall: NSLog(@"ERR: BUFFER TOO SMALL");                    break;
        case kCCMemoryFailure:  NSLog(@"ERR: MEMORY FAILURE");                      break;
        case kCCAlignmentError: NSLog(@"ERR: ALIGNMENT ERROR");                     break;
        case kCCDecodeError:    NSLog(@"ERR: DECODE ERROR");                        break;
        case kCCUnimplemented:  NSLog(@"ERR: UNIMPLEMENTED");                       break;
        case kCCOverflow:       NSLog(@"ERR: OVERFLOW");                            break;
        case (-1):              NSLog(@"ERR: CANNOT UNLOCK, OBJECT NOT LOCKED");    break;
        case (-2):              NSLog(@"ERR: NULL IV");                             break;
        default:                NSLog(@"ERR: UNKNOWN ERROR(%d)",cryptorStatus);     break;
    }
    
    bzero(keyPtr, kCCKeySizeAES256+1);
    free(keyPtr);
    return success;
}

extern inline CCCryptorStatus cryptwork(CCOperation op ,void* dataIn, size_t datalen, char* key, size_t keylen){
    
    int saltlen = 8;
    int ivlen = kCCBlockSizeAES128;
    
    NSData *iv_salt;
    NSMutableArray *ivarray;
    void *dataOut = malloc(datalen);
    bzero(dataOut, datalen);
    size_t dataOutMoved = 0;
    CCCryptorRef cryptorRef = NULL;
    CCCryptorStatus cryptorStatus;
    
    if (ivtable == nil)
        ivtable = [NSMutableDictionary dictionary];
    
    if (op == kCCEncrypt) {
        if ([ivtable objectForKey:getKey(dataIn)] == nil)
            [ivtable setObject:[NSMutableArray array] forKey:getKey(dataIn)];
        
        ivarray = [ivtable objectForKey:getKey(dataIn)];
        
        iv_salt = IMSCryptoUtilsPseudoRandomData(ivlen + saltlen);
        [ivarray insertObject:iv_salt atIndex:0];
    }
    else {
        if ([ivtable objectForKey:getKey(dataIn)] == nil)
            return (cryptorStatus = -1);
        
        ivarray = [ivtable objectForKey:getKey(dataIn)];
        
        iv_salt = [ivarray objectAtIndex:0];
        [ivarray removeObjectAtIndex:0];
    
        if ([ivarray count] == 0)
            [ivtable removeObjectForKey:getKey(dataIn)];
    }
    
    if (iv_salt == nil || [iv_salt bytes] == NULL)
        return (cryptorStatus = -2);
    
    char *_iv = malloc(ivlen);
    char *_salt = malloc(saltlen);
    
    const char *_iv_salt = [iv_salt bytes];
    memcpy(_iv, _iv_salt, ivlen);
    memcpy(_salt, _iv_salt + ivlen, saltlen);

    for(int i = keylen - saltlen; i < keylen; i++)
        key[i] = key [i] ^ _salt[i - keylen + saltlen];
    
    unsigned char *keyhash = malloc(keylen);
    keyhash = CC_SHA256(key, keylen, keyhash);
    
//    printf("_iv:\t");
//    for(int i = 0; i < ivlen; i++){ if(i%4==0) printf(" "); printf("%02x",(unsigned char)_iv[i]); }
//    printf("\n");
//    printf("_salt:\t");
//    for(int i = 0; i < saltlen; i++){ if(i%4==0) printf(" "); printf("%02x",(unsigned char)_salt[i]); }
//    printf("\n");
//    printf("key:\t");
//    for(int i = 0; i < keylen; i++){ if(i%4==0) printf(" "); printf("%02x",(unsigned char)key[i]); }
//    printf("\n");
//    printf("keyhash: ");
//    for(int i = 0; i < keylen; i++){ if(i%4==0) printf(" "); printf("%02x",(unsigned char)keyhash[i]); }
//    printf("\n");

    cryptorStatus = CCCryptorCreateWithMode(op, kCCModeCTR, kCCAlgorithmAES128,
                                            ccNoPadding, _iv,
                                            keyhash, keylen, NULL, 0, 0,
                                            kCCModeOptionCTR_BE,
                                            &cryptorRef);
    
    if (cryptorStatus == kCCSuccess) {
        cryptorStatus = CCCryptorUpdate(cryptorRef,
                                        dataIn, datalen,
                                        dataOut, datalen,
                                        &dataOutMoved);
        if (cryptorStatus == kCCSuccess) {
            cryptorStatus = CCCryptorRelease(cryptorRef);
            memcpy(dataIn, dataOut, datalen);
        }
    }
    
//    NSLog(@"dataOutMoved: %lu",dataOutMoved);
    
    bzero(dataOut, datalen);
    bzero(keyhash, keylen);
    bzero(_iv, kCCBlockSizeAES128);
    bzero(_salt, 8);
    free(dataOut);
    free(keyhash);
    free(_iv);
    free(_salt);
    return cryptorStatus;
}

extern inline BOOL lock(NSObject* obj, NSString* pass) {
    if(handleType(obj, pass, &lock)) {
      return cryptHelper(obj, pass, kCCEncrypt);
    } else
      return YES;
}

extern inline BOOL unlock(NSObject* obj, NSString* pass) {
   if(handleType(obj, pass, &unlock) == YES) {
     return cryptHelper(obj, pass, kCCDecrypt);
    } else
     return YES;
}

extern inline BOOL lockC(void *data, int len, char *pass) {
    BOOL success = YES;
    CCCryptorStatus cryptorStatus;
    
    char *key = malloc(kCCKeySizeAES256 + 1);
    bzero(key, sizeof(key));
    memcpy(key, pass, strlen(pass));
    
    cryptorStatus = cryptwork(kCCEncrypt, data, len, key, kCCKeySizeAES256);
    
    if (cryptorStatus != kCCSuccess)
        success = NO;
    
    bzero(key, sizeof(key));
    free(key);
    return success;
}

extern inline BOOL unlockC(void *data, int len, char *pass) {
    BOOL success = YES;
    CCCryptorStatus cryptorStatus;
    
    char *key = malloc(kCCKeySizeAES256 + 1);
    bzero(key, sizeof(key));
    memcpy(key, pass, strlen(pass));
    
    cryptorStatus = cryptwork(kCCDecrypt, data, len, key, kCCKeySizeAES256);
    
    if (cryptorStatus != kCCSuccess)
        success = NO;
    
    bzero(key, sizeof(key));
    free(key);
    return success;
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
    
    unsigned char* digest = malloc(CC_SHA1_DIGEST_LENGTH);
    if (CC_SHA1((__bridge void*)obj, malloc_size((__bridge void*)obj), digest)) {
        for (NSUInteger i=0; i<CC_SHA1_DIGEST_LENGTH; i++)
            [hex appendFormat:@"%02x", digest[i]];
    }
    free(digest);
    return [NSString stringWithString:hex];
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
