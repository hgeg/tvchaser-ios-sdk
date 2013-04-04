//
//  tvcAPIRequest.m
//  tvchaser
//
//  Created by Can Bülbül on 4/4/13.
//  Copyright (c) 2013 Can Bülbül. All rights reserved.
//

#import "tvcAPIRequest.h"
#import "Base64Transcoder.h"

@implementation tvcAPIRequest

//Singleton
+ (id) sharedRequest {
    static tvcAPIRequest *sharedRequest = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedRequest = [[self alloc] init];
    });
    return sharedRequest;
}

//Initialization
- (id) init {
    if (self = [super init]) {
        oauth_token         = nil;
        oauth_token_secret  = nil;
        access_token        = nil;
        access_token_secret = nil;
        debug               = false;
        state               = 0;
    }
    return self;
}

//TODO: implement debugging
- (BOOL) debugging:(BOOL)dbg {
    debug = dbg;
    return debug;
}

- (NSString *) timestamp {
    return [NSString stringWithFormat:@"%d",((int)[[NSDate date] timeIntervalSince1970])];
}

//Simple HMAC-SHA1 digest method. Derived from gist:1202963
- (NSString *) digest:(NSString *)data withKey: (NSString *)key {
    const NSData *cKey = [key dataUsingEncoding:NSASCIIStringEncoding];
    const NSData *cData = [data dataUsingEncoding:NSASCIIStringEncoding];
    
    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, [cKey bytes], [cKey length], [cData bytes], [cData length], cHMAC);
    
    char base64Result[32];
    size_t theResultLength = 32;
    Base64EncodeData(cHMAC, 20, base64Result, &theResultLength);
    NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
    
    NSString *result = [[NSString alloc] initWithData:theData encoding:NSASCIIStringEncoding];
    
    return result;
}

- (NSString *) nonce {
    double randval = ((double)arc4random() / ARC4RANDOM_MAX);
    NSString *data = [NSString stringWithFormat:@"%@&%@&%f",METHOD,[self timestamp],randval];
    return [self digest:data withKey:CONSUMER_SECRET];
}

- (NSString *) sign:(NSArray *)params withAdditionalKey:(NSString *)tokenSecret {
    NSString *data = [NSString stringWithFormat:@"%@&%@",METHOD, [params componentsJoinedByString:@"&"]];
    NSString *key = CONSUMER_SECRET;
    if(tokenSecret!=nil) key = [NSString stringWithFormat:@"%@&%@",key,tokenSecret];
    return [self digest:data withKey:key];
}

//generic http request method
- (NSDictionary *) http:(NSString *)url withBody:(NSDictionary *)body {
    //create a request
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    //set method
    [request setHTTPMethod:METHOD];
    //set headers
    [request addValue:@"Accept" forHTTPHeaderField:@"application/json"];
    [request addValue:@"Content-Type" forHTTPHeaderField:@"application/json"];
    //set body
    [request setHTTPBody:[NSJSONSerialization dataWithJSONObject:body options:NSJSONWritingPrettyPrinted error:nil]];
    
    //create the response data and send the request
    NSURLResponse *response;
    NSError *err;
    NSData *responseData = [NSURLConnection sendSynchronousRequest:request returningResponse: &response error:&err];
    return [NSJSONSerialization JSONObjectWithData:responseData  options:kNilOptions error:nil];
}

- (BOOL) authenticate {
    NSDictionary *body = nil;
    NSDictionary *responseDict = nil;
    NSString *timestamp, *nonce, *signature;
    NSArray *params;
    BOOL retval = false;
    if(state == init) {
        //OAUTH token:
        //initialize signature
        timestamp = [self timestamp];
        nonce     = [self nonce];
        params     = @[CONSUMER_KEY, timestamp, nonce];
        signature = [self sign:params withAdditionalKey:nil];
        
        //initalize request
        body = @{@"consumer_key":CONSUMER_KEY, @"timestamp":timestamp, @"nonce":nonce, @"signature":signature};
        responseDict = [self http:[NSString stringWithFormat:@"%@request_token/",OAUTH] withBody:body];
        oauth_token = responseDict[@"data"][@"oauth_token"];
        oauth_token_secret = responseDict[@"data"][@"oauth_token_secret"];
        if (![responseDict[@"error"] boolValue]) {
            state = oauth_token_ok;
        }
    }
    if(state == oauth_token_ok){
        //Access token:
        //initialize signature
        timestamp = [self timestamp];
        nonce     = [self nonce];
        params    = @[CONSUMER_KEY, timestamp, nonce, oauth_token];
        signature = [self sign:params withAdditionalKey:oauth_token_secret];
        
        //initalize request
        body = @{@"consumer_key":CONSUMER_KEY, @"timestamp":timestamp, @"nonce":nonce, @"oauth_token":oauth_token, @"signature":signature};
        responseDict = [self http:[NSString stringWithFormat:@"%@access_token/",OAUTH] withBody:body];
        access_token = responseDict[@"data"][@"access_token"];
        access_token_secret = responseDict[@"data"][@"access_token_secret"];
        if (![responseDict[@"error"] boolValue]) {
            state =  access_token_ok;
        }
    }
    if(state == access_token_ok) retval = true;
    return retval;
}

- (NSDictionary *) call:(NSString *)op withParams:(NSDictionary *)params {
    NSString *url = [NSString stringWithFormat:@"%@%@/",CALL,op];
    
    //make sure we're authenticated
    while(![self authenticate]);
    
    NSString *timestamp = [self timestamp];
    NSString *nonce     = [self nonce];
    NSArray  *sparams   = @[CONSUMER_KEY, timestamp, nonce, access_token];
    NSString *signature = [self sign:sparams withAdditionalKey:access_token_secret];
    
    NSDictionary *body;
    if (params!=nil) {
        NSMutableDictionary *data = [[NSMutableDictionary alloc] initWithDictionary:params];
        if((![op isEqualToString:@"login"] &&
           ![op isEqualToString:@"sign_up"] &&
           ![op isEqualToString:@"facebook_connect"]) ){
            data[@"auth_token"] = auth_token;
        }
        body = @{@"consumer_key":CONSUMER_KEY, @"timestamp":timestamp, @"nonce":nonce,@"access_token":access_token,@"signature":signature,@"data":data};
    }else {
        body = @{@"consumer_key":CONSUMER_KEY, @"timestamp":timestamp, @"nonce":nonce,@"access_token":access_token,@"signature":signature};
    }
    NSDictionary *responseDict = [self http:url withBody:body];
    @try {
        if (![responseDict[@"error"] boolValue] && responseDict[@"data"][@"auth_token"] != nil) {
            auth_token = responseDict[@"data"][@"auth_token"];
        }
    }@catch (NSException *exception) {}
    return responseDict;
}

- (void) printData {
    NSLog(@"--------------------------------");
    NSLog(@"tvcAPIRequest Object:");
    NSLog(@"debug: %d, state:%d",debug,state);
    NSLog(@"  OAuth data:");
    NSLog(@"    token: %@",oauth_token);
    NSLog(@"    secret: %@",oauth_token_secret);
    NSLog(@"  Access data:");
    NSLog(@"    token: %@",access_token);
    NSLog(@"    secret: %@",access_token_secret);
    NSLog(@"  Token: %@",auth_token);
    NSLog(@"--------------------------------");
}


@end










