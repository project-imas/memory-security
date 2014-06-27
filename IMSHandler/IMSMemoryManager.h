//
//  IMSMemoryManager.h
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/8/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <Securefoundation/Securefoundation.h>
#import <malloc/malloc.h>

typedef BOOL (*traversalFunc)(NSObject *, NSString *);

extern BOOL track(NSObject* obj);
extern BOOL untrack(NSObject* obj);

extern BOOL wipe(NSObject* obj);
extern int wipeAll();

extern BOOL lock(NSObject* obj, NSString* pass);
extern BOOL unlock(NSObject* obj, NSString* pass);
extern BOOL lockAll(NSString* pass);
extern BOOL unlockAll(NSString* pass) ;

extern BOOL lockC(void *data, int len, char *pass);
extern BOOL unlockC(void *data, int len, char *pass);

extern BOOL checksumTest();
extern NSString* checksumMemHelper(BOOL saveStr);
extern NSString* checksumObj(NSObject* obj);
extern NSString* checksumMem();

NSString* hexString(NSObject* obj);
int getSize(NSObject* obj);
void* getStart(NSObject* obj);
NSString* getKey(void* obj);
BOOL handleType(NSObject* obj, NSString* pass, traversalFunc f);

extern BOOL cryptHelper(NSObject* obj, NSString* pass, CCOperation op);
extern CCCryptorStatus cryptwork(CCOperation op, void* data, size_t datalen, char* key, size_t keylen);