//
//  ViewController.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "ViewController.h"
#import "IMSMemoryManager.h"

@interface ViewController ()

@end

@implementation ViewController

NSArray* arr;
NSString* str;
NSData* data;
NSNumber* num;

BOOL checksumInit = NO;
BOOL strTrack = NO;
BOOL dataTrack = NO;
BOOL numTrack = NO;
BOOL arrTrack = NO;

- (void)viewDidLoad
{
    [super viewDidLoad];

    unsigned char bytes[] = {4,9,5};
    data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    num = [[NSNumber alloc] initWithInt:495];
    str = [[NSString alloc] initWithFormat:@"Four hundred ninety five"];
    
    arr = [[NSArray alloc] initWithObjects:data,num,str,nil];
    
    [self updateWidgets];
}

- (void)updateWidgets
{
    // TODO, consider wiping temp values
    [self.StrLabel setText:str];
    [self.StrHex setText:hexString(str)];
    [self.DataLabel setText:[NSString stringWithFormat: @"%@", data]];
    [self.DataHex setText:hexString(data)];
    [self.NumLabel setText:[NSString stringWithFormat: @"%@", num]];
    [self.NumHex setText:hexString(num)];
    [self.ArrayLabel setText:[NSString stringWithFormat: @"%@", arr]];
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
        [self.StrTrackButton setTitle:@"Track" forState:UIControlStateNormal];
        strTrack = NO;
    } else {
        track(str);
        [self.StrTrackButton setTitle:@"Untrack" forState:UIControlStateNormal];
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
        [self.DataTrackButton setTitle:@"Track" forState:UIControlStateNormal];
        dataTrack = NO;
    } else {
        track(data);
        [self.DataTrackButton setTitle:@"Untrack" forState:UIControlStateNormal];
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
        [self.NumTrackButton setTitle:@"Track" forState:UIControlStateNormal];
        numTrack = NO;
    } else {
        track(num);
        [self.NumTrackButton setTitle:@"Untrack" forState:UIControlStateNormal];
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
        [self.ArrTrackButton setTitle:@"Track" forState:UIControlStateNormal];
        arrTrack = NO;
    } else {
        track(arr);
        [self.ArrTrackButton setTitle:@"Untrack" forState:UIControlStateNormal];
        arrTrack = YES;
    }
}

- (IBAction)WipeAll:(id)sender {
    wipeAll();
    [self updateWidgets];
}

- (IBAction)LockAll:(id)sender {
    lockAll(@"TEST");
    [self updateWidgets];
    
}

- (IBAction)UnlockAll:(id)sender {
    unlockAll(@"TEST");
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
@end
