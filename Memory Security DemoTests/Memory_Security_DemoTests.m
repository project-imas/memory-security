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

static NSString* orig_str = nil;


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

  //** get bytes from string, unfortunately, this does not create a copy, but only a byte filter of the data
  NSData* byte_representation = [str dataUsingEncoding:NSUTF8StringEncoding];
  //** need to copy to actual bytes in NSData object
  NSData* sdata = [NSData dataWithData:byte_representation];
  orig = [NSData dataWithData:sdata];
  STAssertTrue([sdata isEqualToData:orig], @"sdata is not the same as original");
  lock(sdata, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertFalse([sdata isEqualToData:orig], @"encrypted sdata same as original");
  //** unlocking should return it to the original value
  unlock(sdata, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertTrue([sdata isEqualToData:orig], @"sdata is not the same as original");

  //** test locking string object
  orig_str = [NSMutableString stringWithString: str];
  lock(str, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertFalse([str isEqualToString:orig_str], @"encrypted sdata same as original");
  //** unlocking should return it to the original value
  unlock(str, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertTrue([str isEqualToString:orig_str], @"sdata is not the same as original");

  //** test locking string object
  orig_str = [[NSString alloc] initWithFormat:str]; //@"Four hundred ninety five"];
  //** does not work; makes a reference to the original string
  // error - [NSMutableString stringWithString: str];
  // error - NSString *orig_str = [str copy];
  lock(orig_str, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertFalse([orig_str isEqualToString:str], @"encrypted sdata same as original");
  //** need to test if str is actually encrypted, b/c it is not
  //** unlocking should return it to the original value
  unlock(orig_str, @"927FBDBF-E58E-43F7-B3E0-A245C7C90A0C");
  STAssertTrue([orig_str isEqualToString:str], @"sdata is not the same as original");


}

- (void)testLockC_UnLockC
{
    
    //** locking obj should encrypt it
    int len = 50;
    void *data = malloc(len);
    void *orig = malloc(len);
    memset(data, 0x5a, len);
    memset(orig, 0x5a, len);
    
    //** make sure key is 32 bytes
    lockC(data, len, @"passwordpasswordpasswordpassword");
    NSData *dataD = [NSData dataWithBytesNoCopy:data length:len freeWhenDone:NO];
    NSData *origD = [NSData dataWithBytesNoCopy:orig length:len freeWhenDone:NO];
    STAssertFalse([dataD isEqualToData:origD], @"encrypted data same as original");

    unlockC(data, len, @"passwordpasswordpasswordpassword");
    dataD = [NSData dataWithBytesNoCopy:data length:len freeWhenDone:NO];
    STAssertTrue([dataD isEqualToData:origD], @"data is not the same as original");
    
    free(data);
    free(orig);
}


@end
