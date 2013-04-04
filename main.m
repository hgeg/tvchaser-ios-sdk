//
//  main.m
//  tvchaser
//
//  Created by Can Bülbül on 4/4/13.
//  Copyright (c) 2013 Can Bülbül. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "tvcAPIRequest.h"

int main(int argc, char *argv[])
{
    NSLog(@"first test for authentication only:");
    tvcAPIRequest *request = [tvcAPIRequest sharedRequest];
    NSLog(@"request object created");
    [request printData];
    NSLog(@"\n");
    [request authenticate];
    NSLog(@"authentication completed");
    [request printData];
    NSLog(@"\n");
    NSLog(@"second test: login api call");
    request = nil;
    request = [tvcAPIRequest sharedRequest];
    NSLog(@"request object created");
    [request printData];
    NSLog(@"\n");
    NSDictionary *response;
    NSLog(@"Logging in\n");
    response = [request call:@"login" withParams:@{@"email":@"test@example.com", @"password":@"test_example"}];
    NSLog(@"response: %@",response);
    NSLog(@"request object should have an auth_token now.");
    [request printData];
    NSLog(@"Trying an autheticated api call\n");
    response = [request call:@"popular" withParams:@{}];
    NSLog(@"response: %@",response);
    NSLog(@"Test finished.");
}
