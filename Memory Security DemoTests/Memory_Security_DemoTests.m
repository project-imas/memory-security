//
//  Memory_Security_DemoTests.m
//  Memory Security DemoTests
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "Memory_Security_DemoTests.h"
#import "IMSMemoryManager.h"

@implementation Memory_Security_DemoTests

NSArray* arr;
NSString* str;
NSData* data;
NSNumber* num;

BOOL checksumInit = NO;
BOOL strTrack = NO;
BOOL dataTrack = NO;
BOOL numTrack = NO;
BOOL arrTrack = NO;



- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
    unsigned char bytes[] = {4,9,5};
    data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    num = [[NSNumber alloc] initWithInt:495];
    str = [[NSString alloc] initWithFormat:@"Four hundred ninety five"];
    
    arr = [[NSArray alloc] initWithObjects:data,num,str,nil];
    
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

- (void)testWipe
{
    BOOL res = wipe(data);
    NSInteger len = [data length];
    if (res == false)
      STFail(@"Wipe failed");

    uint8_t *bytes = malloc(len);
    memset(bytes, 0, len);
    NSData *zeros = [NSData dataWithBytesNoCopy:bytes length:len];
    STAssertTrue([data isEqualToData:zeros], @"wipe test not zeroing data properly");
}

- (void)testLock_UnLock
{
  //** locking obj should encrypt it
  NSData *orig = [NSData dataWithData:data];
  STAssertTrue([data isEqualToData:orig], @"data is not the same as original");
  lock(data, @"pass");
  STAssertFalse([data isEqualToData:orig], @"encrypted data same as original");
  //** unlocking should return it to the original value
  unlock(data, @"pass");
  STAssertTrue([data isEqualToData:orig], @"data is not the same as original");


}


@end
