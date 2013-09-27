//
//  IMSMemoryManager.h
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <Foundation/Foundation.h>

//** define securefoundation to make use of openSSL
//** when undefined, Apple CommonCrypto will be used
#define iMAS_SecureFoundation

#ifdef iMAS_SecureFoundation
#import <Securefoundation/Securefoundation.h>

#else
//** default - apple crypto, securefoundation not needed
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#endif

#import <malloc/malloc.h>

//
//  IMSMemoryManager.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "IMSMemoryManager.h"


typedef BOOL (*traversalFunc)(NSObject *, NSString *);

// Return NO if wipe failed
extern inline BOOL wipe(NSObject* obj);
// Return NO if object already tracked
extern inline BOOL track(NSObject* obj);

extern inline BOOL untrack(NSObject* obj);
extern inline int wipeAll();
extern inline BOOL lock(NSObject* obj, NSString* pass);
extern inline BOOL unlock(NSObject* obj, NSString* pass);
extern inline BOOL lockAll(NSString* pass);

extern inline BOOL unlockAll(NSString* pass) ;

extern inline BOOL checksumTest();
extern inline NSString* checksumMemHelper(BOOL saveStr);
extern inline NSString* checksumObj(NSObject* obj);
extern inline NSString* checksumMem();

NSString* hexString(NSObject* obj);

extern inline BOOL lockC(u_int8_t *buf, int len, NSString* pass);
extern inline BOOL unlockC(u_int8_t *buf, int len, NSString* pass);


