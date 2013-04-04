//
//  tvcAPIRequest.h
//  tvchaser
//
//  Created by Can Bülbül on 4/4/13.
//  Copyright (c) 2013 Can Bülbül. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>
#include <stdlib.h>

#define BASE_URL        @"http://tvchaser.com/"
#define OAUTH           @"http://tvchaser.com/api/oauth_1/"
#define CALL            @"http://tvchaser.comapi/call/"
#define METHOD          @"POST"
#define CONSUMER_KEY    @"--your-consumer-key"
#define CONSUMER_SECRET @"--your-consumer-key"

#define ARC4RANDOM_MAX  0x100000000

typedef enum {
    init   = 0,
    oauth_token_ok  = 1,
    access_token_ok = 2
} states;

@interface tvcAPIRequest : NSObject
{
    NSString *oauth_token;
    NSString *oauth_token_secret;
    
    NSString *access_token;
    NSString *access_token_secret;
    
    NSString *auth_token;
    
    BOOL debug;
    states state;
}

//Singleton
+ (id) sharedRequest;

//Model
- (id) init;
- (BOOL) debugging:(BOOL) dbg;
- (void) printData;

//Authentication methods
- (NSString *) timestamp;
- (NSString *) digest:(NSString *)data withKey:(NSString *)key;
- (NSString *) nonce;
- (NSString *) sign:(NSArray *)params withAdditionalKey:(NSString *)tokenSecret;
- (NSDictionary *) http:(NSString *)url withBody:(NSDictionary *)body;
- (BOOL) authenticate;

//API call functions
//- (NSDictionary *) call: (NSString *)call;
- (NSDictionary *) call:(NSString *)op withParams:(NSDictionary *)params;


@end
