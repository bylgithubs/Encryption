//
//  SCRSACryptor.m
//  SmartCity
//
//  Created by hoperun on 15/11/12.
//  Copyright (c) 2015年 sea. All rights reserved.
//

#import "SCRSACryptor.h"
#import "BDRSACryptor.h"
#import "BDRSACryptorKeyPair.h"
#import "BDError.h"
#import "BDLog.h"

@interface SCRSACryptor ()
{
    NSString *kPublicText;
    NSString *kprivateText;
}
@end
@implementation SCRSACryptor

- (id)initWithPrivateKey:(NSString *)privateKey publicKey:(NSString *)publicKey{
    self = [super init];
    if (self) {
        kPublicText = publicKey;
        kprivateText = privateKey;
    }
    return self;
}
//解密
- (NSString *)decryptString:(NSString *)ciphertext{
    BDError *error = [[BDError alloc] init];
    BDRSACryptor *RSACryptor = [[BDRSACryptor alloc] init];
    NSString *privateKey = [self formattedPEMString:kprivateText];
    BDRSACryptorKeyPair *RSAKeyPair = [[BDRSACryptorKeyPair alloc] initWithPublicKey:@""
                                                                          privateKey:privateKey];
    NSString *recoveredText =
    [RSACryptor decrypt:[ciphertext stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
                    key:RSAKeyPair.privateKey
                  error:error];
    return recoveredText;
}
//加密
- (NSString *)encryptString:(NSString *)expressText{
    BDError *error = [[BDError alloc] init];
    BDRSACryptor *RSACryptor = [[BDRSACryptor alloc] init];
    NSString *publicKey = [self formatPublicKey:kPublicText];
    BDRSACryptorKeyPair *RSAKeyPair = [[BDRSACryptorKeyPair alloc] initWithPublicKey:publicKey
                                                                          privateKey:@""];
    NSString *cipherText =
    [RSACryptor encrypt:expressText
                    key:RSAKeyPair.publicKey
                  error:error];
    NSString *ciphertext = (NSString*)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(nil,(CFStringRef)cipherText, nil,(CFStringRef)@"!*'();:@&=+$,/?%#[]", kCFStringEncodingUTF8));
    return ciphertext;
}
//生成公私钥
- (void)generateKeysExample
{
    BDError *error = [[BDError alloc] init];
    BDRSACryptor *RSACryptor = [[BDRSACryptor alloc] init];
    
    BDRSACryptorKeyPair *RSAKeyPair = [RSACryptor generateKeyPairWithKeyIdentifier:@"key_pair_tag"
                                                                             error:error];
    
    BDDebugLog(@"Private Key:\n%@\n\nPublic Key:\n%@", RSAKeyPair.privateKey, RSAKeyPair.publicKey);
    
    [self encryptionCycleWithRSACryptor:RSACryptor
                                keyPair:RSAKeyPair
                                  error:error];
}
//导入公私钥
- (void)importKeysExample
{
    BDError *error = [[BDError alloc] init];
    BDRSACryptor *RSACryptor = [[BDRSACryptor alloc] init];
    
    //从pem文件读取
//    NSString *privateKey1 = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"rsa_private_key" ofType:@"txt"]
//                                                      encoding:NSUTF8StringEncoding
//                                                         error:nil];
//    
//    NSString *publicKey1 = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"rsa_public_key" ofType:@"txt"]
//                                                     encoding:NSUTF8StringEncoding
//                                                        error:nil];
    //从字符串读取
    NSString *privateKey = [self formattedPEMString:kprivateText];
    NSString *publicKey = [self formatPublicKey:kPublicText];
    BDRSACryptorKeyPair *RSAKeyPair = [[BDRSACryptorKeyPair alloc] initWithPublicKey:publicKey
                                                                          privateKey:privateKey];
    
    [self encryptionCycleWithRSACryptor:RSACryptor
                                keyPair:RSAKeyPair
                                  error:error];
}
//加解密Demo
- (void)encryptionCycleWithRSACryptor:(BDRSACryptor *)RSACryptor
                              keyPair:(BDRSACryptorKeyPair *)RSAKeyPair
                                error:(BDError *)error
{
    NSString *cipherText =
    [RSACryptor encrypt:@"Plain Text"
                    key:RSAKeyPair.publicKey
                  error:error];
    
    NSString *recoveredText =
    [RSACryptor decrypt:cipherText
                    key:RSAKeyPair.privateKey
                  error:error];
    
    BDDebugLog(@"Recovered Text:\n%@", recoveredText);
}
//格式化私钥
- (NSString *)formattedPEMString:(NSString *)originalString
{
    NSString *trimmedString = [originalString stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    const char *c = [trimmedString UTF8String];
    int len = [trimmedString length];
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int index = 0;
    while (index < len) {
        char cc = c[index];
        [result appendFormat:@"%c", cc];
        if ( (index+1) % 64 == 0)
        {
            [result appendString:@"\n"];
        }
        index++;
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    return result;
}
//格式化公钥
- (NSString *)formatPublicKey:(NSString *)publicKey {
    
    NSMutableString *result = [NSMutableString string];
    
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    
    int count = 0;
    
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 76) {
            [result appendString:@"\n"];
            count = 0;
        }
        
    }
    
    [result appendString:@"\n-----END PUBLIC KEY-----\n"];
    
    return result;
    
}
@end
