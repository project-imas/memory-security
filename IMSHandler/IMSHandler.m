//
//  IMSHandler.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/2/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <malloc/malloc.h>
#import "IMSHandler.h"

@implementation IMSHandler

static NSPointerArray* unlockedPointers;
static NSMutableArray* lockedPointers;
static NSString* checksumStr;

+(NSPointerArray*) unlockedPointers {
    if(!unlockedPointers) {
       unlockedPointers =[[NSPointerArray alloc] init];
    }
    return unlockedPointers;
}

// Return NO if object already tracked
+ (BOOL) track:(NSObject *)obj {
    [[self unlockedPointers] addPointer:(void *)obj];
    NSLog(@"TRACK %p -- %d", obj, [[self unlockedPointers] count]);
    return YES;
}

+ (BOOL) untrack:(NSObject *)obj {
    
    for(int i = 0; i < [[self unlockedPointers] count]; i ++){
        if([[self unlockedPointers] pointerAtIndex:i] == (__bridge void *)(obj)){
            [[self unlockedPointers] removePointerAtIndex:i];
        }
    }
    
    return YES;
}

+ (void *) getStart:(NSObject *) obj {
    if([obj isKindOfClass:[NSString class]]) {
        return ((__bridge void*)obj + 9);
    } else if([obj isKindOfClass:[NSData class]]) {
        return ((__bridge void*)obj + 10);
    } else {
        return NULL;
    }
}

+ (int) getSize:(NSObject *) obj {
    if([obj isKindOfClass:[NSString class]]) {
        return (malloc_size((__bridge void*)obj) - 9);
    } else if([obj isKindOfClass:[NSData class]]) {
        return (malloc_size((__bridge void*)obj) - 10);
    } else {
        return NULL;
    }
}

// Return NO if wipe failed
+ (BOOL) wipe:(NSObject *)obj {
    NSLog(@"Object pointer: %p", obj);
    memset( [self getStart:obj], 0, [self getSize:obj]);
    return YES;
}

// Return count of how many wiped
+ (int) wipeAll {
    for(id obj in [self unlockedPointers]) [self wipe:obj];
    
    return [[self unlockedPointers] count];
}

// Return YES is the object was encrypted
+ (BOOL) crypt:(NSObject*) obj
              :(NSString *)pass
              :(CCOperation) op {
    NSLog(@"Object pointer: %p", obj);
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [pass getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
        
    size_t bufferSize = [self getSize:obj] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    NSUInteger dataLength = [self getSize:obj];

    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(op, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL,
                                          (__bridge void*)obj + 9,
                                          dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    memcpy([self getStart:obj], buffer, [self getSize:obj]);
    free(buffer);
    
    // TODO: Make sure key is wiped
    // TODO: Return based on cryptStatus  --  if (cryptStatus == kCCSuccess)
    return YES;
}

+ (BOOL) lock:(NSObject *)obj :(NSString *)pass {
    return [self crypt:obj :pass :kCCEncrypt];
}

+ (BOOL) unlock:(NSObject *) obj:(NSString *)pass {
    return [self crypt:obj :pass :kCCDecrypt];
}

+ (BOOL) lockAll:(NSObject *) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (BOOL) unlockAll:(NSObject *) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (BOOL) checksumTest {
    NSString* checksumTmp = [checksumStr copy];
    NSString* newSum = [self checksum];
    
    if([checksumTmp isEqualToString:newSum]) return YES;
    else return NO;
}

+ (NSString *) checksum:(NSObject *) obj {
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

+ (NSString *) checksum {
    NSMutableString *hex = [[NSMutableString alloc] init];

    for(id obj in [self unlockedPointers]) {
        [hex appendFormat:@"%p", obj];
        [hex appendString:[self checksum:obj]];
    }
    checksumStr = [NSString stringWithString:hex];
    return [checksumStr copy];
}

@end
