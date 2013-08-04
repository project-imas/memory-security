//
//  IMSHandler.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/2/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <malloc/malloc.h>
#import "IMSHandler.h"

@implementation IMSHandler

static NSPointerArray* unlockedPointers;
static NSMutableArray* lockedPointers;
static NSString* checksum = NULL;

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
    NSLog(@"NOT IMPLEMENTED");
    
    return YES;
}

// Return NO if wipe failed
+ (BOOL) wipe:(NSObject *)obj {
    NSLog(@"Object pointer: %p", obj);
    if([obj isKindOfClass:[NSString class]]) {
        memset ( (__bridge void*)obj + 9
                , 0
                , malloc_size((__bridge void*)obj) - 9
                );
    } else if([obj isKindOfClass:[NSData class]]) {
        NSLog(@"DATA");
        //     NSLog(@"%d -- %d -- %d", [str length], malloc_size((__bridge void*)obj), malloc_size((__bridge void*)foob));
        NSData* data = (NSData*)obj;
        memset([data bytes], 0, [data length]);
        NSLog(@"%p -- %p", [data bytes], (__bridge void*)obj);
        //   NSLog(@">>%p", [data bytes]);
    } else {
        NSLog(@"Wiping of object type not supported yet");
    }
    return YES;
}

// Return YES if all wiped, NO otherwise
+ (BOOL) wipeAll {
    NSLog(@"WIPE ALL %d", [[self unlockedPointers] count]);
    for(id obj in [self unlockedPointers]) {
        NSLog(@">>>%p", obj);
        [self wipe:obj];
    }
    return YES;
}

// Return YES is the object was encrypted
+ (BOOL) lock:(NSObject*) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (BOOL) unlock:(NSObject *) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (BOOL) lockAll:(NSObject *) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (BOOL) unlockAll:(NSObject *) obj:(NSString *)pass {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (NSString *) checksumStore {
    NSLog(@"NOT IMPLEMENTED");
    
    return @"";
}

+ (BOOL) checksumTest {
    NSLog(@"NOT IMPLEMENTED");

    return YES;
}

+ (NSString *) checksum {
    NSLog(@"NOT IMPLEMENTED");

    return @"";
}

@end
