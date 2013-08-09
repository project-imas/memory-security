//
//  IMSMemoryManager.h
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <malloc/malloc.h>

//
//  IMSMemoryManager.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "IMSMemoryManager.h"


typedef BOOL (*traversalFunc)(NSObject *);

// Return NO if wipe failed
BOOL wipe(NSObject* obj);
// Return NO if object already tracked
BOOL track(NSObject* obj);

BOOL untrack(NSObject* obj);
int wipeAll();
BOOL lock(NSObject* obj, NSString* pass);
BOOL unlock(NSObject* obj, NSString* pass);
BOOL lockAll(NSObject* obj, NSString* pass);

BOOL unlockAll(NSObject* obj, NSString* pass) ;

BOOL checksumTest();

NSString* checksumObj(NSObject* obj);

NSString* checksumMem();