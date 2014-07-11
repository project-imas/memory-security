//
//  ViewController.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//
#import <sys/mman.h>
#import <dlfcn.h>

#import "ViewController.h"
#import "IMSMemoryManager.h"

@interface ViewController ()

@end

@implementation ViewController

NSArray* arr;
NSString* str;
NSData* data;
NSNumber* num;
NSDictionary *dict;

BOOL checksumInit = NO;
BOOL strTrack = NO;
BOOL dataTrack = NO;
BOOL numTrack = NO;
BOOL arrTrack = NO;

BOOL readyToExit = NO;

- (void)viewDidLoad
{
    [super viewDidLoad];

    unsigned char bytes[] = {0xde,0xad,0xbe,0xef};
    data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    num = [[NSNumber alloc] initWithInt:0xbebafeca];
    str = [[NSString alloc] initWithFormat:@"0123456789ABCDEF"];
    
    arr = [[NSArray alloc] initWithObjects:data,num,str,nil];
    dict = [NSDictionary dictionaryWithObjects:arr forKeys:
            [NSArray arrayWithObjects:
             [NSString stringWithFormat:@"data"],
             [NSString stringWithFormat:@"num"],
             [NSString stringWithFormat:@"str"], nil]];
    
    [self updateWidgets];
    
    validate();
}

- (void)updateWidgets
{
    // TODO, consider wiping temp values
    [self.StrLabel setText:[NSString stringWithFormat:@"%@",str]];
    [self.StrHex setText:[NSString stringWithFormat:@"%@",hexString(str)]];
    [self.DataLabel setText:[NSString stringWithFormat: @"%@", data]];
    [self.DataHex setText:[NSString stringWithFormat:@"%@",hexString(data)]];
    [self.NumLabel setText:[NSString stringWithFormat: @"%@", num]];
    [self.NumHex setText:[NSString stringWithFormat:@"%@",hexString(num)]];
    [self.ArrayLabel setText:[NSString stringWithFormat: @"%@", [arr componentsJoinedByString:@", "]]];

}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)StrWipe:(id)sender {
    wipe(str);
    [self updateWidgets];
}

- (IBAction)StrLock:(id)sender {
    lock(str, @"PASS");
    [self updateWidgets];
}

- (IBAction)StrUnlock:(id)sender {
    unlock(str, @"PASS");
    [self updateWidgets];
}

- (IBAction)StringTrack:(id)sender {
    if(strTrack == YES) {
        untrack(str);
        [self.StrTrackButton setTitle:@"track" forState:UIControlStateNormal];
        strTrack = NO;
    } else {
        track(str);
        [self.StrTrackButton setTitle:@"untrack" forState:UIControlStateNormal];
        strTrack = YES;
    }
}

- (IBAction)DataWipe:(id)sender {
    wipe(data);
    [self updateWidgets];
}

- (IBAction)DataLock:(id)sender {
    lock(data, @"PASS");
    [self updateWidgets];
}

- (IBAction)DataUnlock:(id)sender {
    unlock(data, @"PASS");
    [self updateWidgets];
}

- (IBAction)DataTrack:(id)sender {
    if(dataTrack == YES) {
        untrack(data);
        [self.DataTrackButton setTitle:@"track" forState:UIControlStateNormal];
        dataTrack = NO;
    } else {
        track(data);
        [self.DataTrackButton setTitle:@"untrack" forState:UIControlStateNormal];
        dataTrack = YES;
    }
}

- (IBAction)NumberWipe:(id)sender {
    wipe(num);
    [self updateWidgets];
}

- (IBAction)NumberLock:(id)sender{
    lock(num, @"PASS");
    [self updateWidgets];
}

- (IBAction)NumberUnlock:(id)sender {
    unlock(num, @"PASS");
    [self updateWidgets];    
}

- (IBAction)NumberTrack:(id)sender {
    if(numTrack == YES) {
        untrack(num);
        [self.NumTrackButton setTitle:@"track" forState:UIControlStateNormal];
        numTrack = NO;
    } else {
        track(num);
        [self.NumTrackButton setTitle:@"untrack" forState:UIControlStateNormal];
        numTrack = YES;
    }
}

- (IBAction)ArrayWipe:(id)sender {
    wipe(arr);
    [self updateWidgets];
}

- (IBAction)ArrayLock:(id)sender {
    lock(arr, @"PASS");
    [self updateWidgets];
}

- (IBAction)ArrayUnlock:(id)sender {
    unlock(arr, @"PASS");
    [self updateWidgets];
}

- (IBAction)ArrayTrack:(id)sender {
    if(arrTrack == YES) {
        untrack(arr);
        [self.ArrTrackButton setTitle:@"track" forState:UIControlStateNormal];
        arrTrack = NO;
    } else {
        track(arr);
        [self.ArrTrackButton setTitle:@"untrack" forState:UIControlStateNormal];
        arrTrack = YES;
    }
}

- (IBAction)WipeAll:(id)sender {
    wipeAll();
    [self updateWidgets];
}

- (IBAction)LockAll:(id)sender {
    lockAll(@"PASS");
    [self updateWidgets];
    
}

- (IBAction)UnlockAll:(id)sender {
    unlockAll(@"PASS");
    [self updateWidgets];
}

- (IBAction)ChecksumAll:(id)sender {
    UIAlertView* alert;
    if(checksumInit == NO) {
       alert = [[UIAlertView alloc] initWithTitle:@"Checksum Saved" message:@"Subsequent checksum comparison will  alert whether there was a change or not" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
        checksumInit = YES;
        checksumMem();
    } else {
        if(checksumTest()) {
          alert = [[UIAlertView alloc] initWithTitle:@"Checksum Matched" message:@"The memory of tracked objects has not changed" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
        } else {
          alert = [[UIAlertView alloc] initWithTitle:@"Checksum Failed" message:@"The memory of tracked objects was different" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];  
        }
    }
    [alert show];
}

- (IBAction)SecureExit:(id)sender {
    if (readyToExit)
        exit(0);
    else {
        secureExit();
        [self.ExitButton setTitle:@"exit"];
        [self updateWidgets];
        readyToExit = YES;
    }
}
@end
