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


// Return NO if object already tracked
+ (BOOL) track:(NSObject *)obj {
    NSLog(@"NOT IMPLEMENTED");
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
+ (BOOL) wipeAll:(NSObject *)obj {
    NSLog(@"NOT IMPLEMENTED");

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

@end
