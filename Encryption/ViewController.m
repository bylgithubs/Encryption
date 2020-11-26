//
//  ViewController.m
//  Encryption
//
//  Created by Civet on 2020/11/21.
//  Copyright © 2020 PersonalONBYL. All rights reserved.
//

#import "ViewController.h"
#import <MF_Base64Additions.h>
#import "CommonCrypto/CommonDigest.h"
#import "CommonCrypto/CommonCryptor.h"
#import "RSAEncrypt.h"
#import <Base64.h>
#import <LocalAuthentication/LocalAuthentication.h>

@interface ViewController ()

@property(nonatomic, strong)NSString *str;

@end

@implementation ViewController

static NSString *mPublicKey = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL4WFHzKSzecLYdqnyteM/UmUBUm5HKph1dPpvqHH8G+lkcd9ohSmnRNq5JEZVFXmU8ApezLf8XLz5Wz8yLFIPE14hqKdFpyfWi7Qyu/kk8q3I9Z521BSlxO+uVaBRjXBHXKzZy5acFVUz40YpMW/W6dcVlNjmU8WHaXaUJHODWQIDAQAB-----END PUBLIC KEY-----";
static NSString *mPrivateKey = @"-----BEGIN ENCRYPTED PRIVATE KEY-----MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIPhnrloSEVukCAggAMBQGCCqGSIb3DQMHBAinzxmWm/SKugSCAoDzzgu0znOZzP9wcBGElnlfpn6urxLs4xxa7eJbSFlZFxDmEZ5iPP0v3NXEKptID6tuXi928eGtt93RlYJ+j3KxgLt+r15VYAycRul0a/lOLGQLd78PpY99Ein/C4A/YvkXaGDALaxyZf4v8xS0erIPSm61n2ek+iOE8+AFvxpLzjabYrqrCC36wPg83DMTWSzRhV+kOvVnSGp3ZbXYXu0UuHLXLK3x0BCpX6RS/r9fRfgrHK+Uu0XnyYjtlgcmUs3xU3wlPJOFYkWnA9xV2C4Ohkp3wnRUs7HfFLjIhEwvbjuziNdNqIaE6hhpmKyaIC2ChjjXcK7VSA6vgAZuo0cU/yTpsiJmKn87s5DrAAHRPIjQAiH2jtM7k0cQg/zLFW0qyegerWCqp5QKymPy04MOdewZd4BHuN5qAy+4b/InkRtHwMzf4ayA/vVjqCZHLWDqif+F338atkRHts0H7zk6wZ4F2AQfhpUjujJa9063xAizGNOznETXNU8cOc3zYl/TOouQOKd1Vj4Zi5xaNHkMceP9qsENn+HCBefT36f8txvUt1M5jw7PQEOKWtrsaIiP2a87TwpNbO/fcJuJ7d1bX+K6ZtWwM/xlkdL/IRZZX1n3hnIADxiDkDhffkHH3P6rd+RUzt3IicuBBK4Xq5zMNggfrV4gJRvw7vw8m8Wp87wPtySHf5OzLR/abX5ilZDxgRV3XWHFHr/3yPcjTtM6CwwQ5dWVmp69pCMcKEBaoLmK0h/ty7RYS/dav2RKF9TNxOjffkH+DbsZGG4bqUms8+roQvuu2gKiEavh7q+bs1Dbw4JK2pDZxYo30DLf7R+zSfEcblDAK/wv33YW6NCW-----END ENCRYPTED PRIVATE KEY-----";
//static NSString *mPublicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL4WFHzKSzecLYdqnyteM/UmUBUm5HKph1dPpvqHH8G+lkcd9ohSmnRNq5JEZVFXmU8ApezLf8XLz5Wz8yLFIPE14hqKdFpyfWi7Qyu/kk8q3I9Z521BSlxO+uVaBRjXBHXKzZy5acFVUz40YpMW/W6dcVlNjmU8WHaXaUJHODWQIDAQAB";
//static NSString *mPrivateKey = @"MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIPhnrloSEVukCAggAMBQGCCqGSIb3DQMHBAinzxmWm/SKugSCAoDzzgu0znOZzP9wcBGElnlfpn6urxLs4xxa7eJbSFlZFxDmEZ5iPP0v3NXEKptID6tuXi928eGtt93RlYJ+j3KxgLt+r15VYAycRul0a/lOLGQLd78PpY99Ein/C4A/YvkXaGDALaxyZf4v8xS0erIPSm61n2ek+iOE8+AFvxpLzjabYrqrCC36wPg83DMTWSzRhV+kOvVnSGp3ZbXYXu0UuHLXLK3x0BCpX6RS/r9fRfgrHK+Uu0XnyYjtlgcmUs3xU3wlPJOFYkWnA9xV2C4Ohkp3wnRUs7HfFLjIhEwvbjuziNdNqIaE6hhpmKyaIC2ChjjXcK7VSA6vgAZuo0cU/yTpsiJmKn87s5DrAAHRPIjQAiH2jtM7k0cQg/zLFW0qyegerWCqp5QKymPy04MOdewZd4BHuN5qAy+4b/InkRtHwMzf4ayA/vVjqCZHLWDqif+F338atkRHts0H7zk6wZ4F2AQfhpUjujJa9063xAizGNOznETXNU8cOc3zYl/TOouQOKd1Vj4Zi5xaNHkMceP9qsENn+HCBefT36f8txvUt1M5jw7PQEOKWtrsaIiP2a87TwpNbO/fcJuJ7d1bX+K6ZtWwM/xlkdL/IRZZX1n3hnIADxiDkDhffkHH3P6rd+RUzt3IicuBBK4Xq5zMNggfrV4gJRvw7vw8m8Wp87wPtySHf5OzLR/abX5ilZDxgRV3XWHFHr/3yPcjTtM6CwwQ5dWVmp69pCMcKEBaoLmK0h/ty7RYS/dav2RKF9TNxOjffkH+DbsZGG4bqUms8+roQvuu2gKiEavh7q+bs1Dbw4JK2pDZxYo30DLf7R+zSfEcblDAK/wv33YW6NCW";

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
//    NSDate *date = [NSDate date];
//    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
//    formatter.dateFormat = @"yyyy-MM-dd HH:mm";
//    NSString *dateStr = [formatter stringFromDate:date];
    
    NSString *sysV =  [[UIDevice currentDevice] systemVersion];
    //base64加密、解密
    [self base64EncodeAndDecode];
    //md5加密、验证
    [self md5Signature];
    //AES加密、解密
    [self aesEncodeAndDecode];
    //RSA加密、解密
    [self rsaEncodeAndDecode];
    [self fingerprintIdentification];
    
}

- (void)fingerprintIdentification{
    float version = [UIDevice currentDevice].systemVersion.floatValue;
    if (version < 8.0) {
        NSLog(@"系统版本太低，请升级至最新系统");
        return;
    }
    LAContext *laCtx = [[LAContext alloc] init];
    if (![laCtx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL]) {
        NSLog(@"该设备不支持指纹识别功能");
        return;
    }
    [laCtx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"指纹登录" reply:^(BOOL success, NSError * _Nullable error) {
        if (success) {
            NSLog(@"指纹识别成功");
        } else {
            NSLog(@"指纹识别失败");
        }
    }];
}

//RSA
- (void)rsaEncodeAndDecode{
    //使用RSA执行加密操作
    NSString *rsaString = @"this is a few information of use of RSA";
    NSString *rsaEncodeString = [RSAEncrypt encryptString:rsaString
                                              publicKey:mPublicKey];
    NSLog(@"rsaEncodeString : %@", rsaEncodeString);

    //使用RSA执行解密操作
    NSString *rsaDecodeString = [RSAEncrypt decryptString:rsaEncodeString
                                             privateKey:mPrivateKey];
    NSLog(@"rsaDecodeString : %@", rsaDecodeString);
}

//AES
- (void)aesEncodeAndDecode{
    //使用AES执行加密操作
    NSString *aesKey = @"aesKey20201124";
    NSString *aesEncodeString = @"this is a little encode information";
    NSData *aesKeyData = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aesSourceData = [aesEncodeString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aesEncodeData = [ViewController aesEncryptData:aesSourceData key:aesKeyData];
    NSLog(@"aesEncodeData: %@",aesEncodeData);
    
    //使用AES执行解密操作
    NSString *aesDecodeString = nil;
    NSData *aesDecodeData = [ViewController aesDecryptData:aesEncodeData key:aesKeyData];
    aesDecodeString = [[NSString alloc] initWithData:aesDecodeData encoding:NSUTF8StringEncoding];
    NSLog(@"aesDecodeString: %@",aesDecodeString);
    
}

//md5
- (void)md5Signature{
    NSString *string = @"it will sigature use of md5";
    NSString *md5EncodeString = [ViewController md5SignWithString:string];
    NSLog(@"md5EncodeString: %@",md5EncodeString);
    
    //MD5为不可逆的操作，使用MD5执行验签操作
    NSString *md5VerifyString = [ViewController md5SignWithString:string];
    NSLog(@"md5VerifyString: %@",md5VerifyString);
    if ([md5VerifyString isEqualToString:md5EncodeString]) {
        NSLog(@"md5 verify sign success");
    } else {
        NSLog(@"md5 verify sign failed");
    }
}

//base64
- (void)base64EncodeAndDecode{
    NSString *string = @"hello,this is a little data";
    //加密
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
//    NSString *base64EncodeString = [MF_Base64Codec base64StringFromData:data];
    NSString *base64EncodeString = [string base64EncodedString];
    NSLog(@"base64EncodeString:%@",base64EncodeString);
    
    //解密
    NSString *base64DecodeString = nil;
    NSData *base64DecodeData = [MF_Base64Codec dataFromBase64String:base64EncodeString];
//    base64DecodeString = [[NSString alloc] initWithData:base64DecodeData encoding:NSUTF8StringEncoding];
    base64DecodeString = [base64EncodeString base64DecodedString];
    NSLog(@"base64DecodeString:%@",base64DecodeString);
}



//base64加密
+ (NSString *)base64EncodedStringWithData:(NSData *)data{
    if (data == nil || data == NULL) {
        return nil;
    }else if (![data isKindOfClass:[NSData class]]){
        return nil;
    }
    
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }
    
    NSDataBase64EncodingOptions options;
    options = NSDataBase64EncodingEndLineWithLineFeed;
    return [data base64EncodedStringWithOptions:options];
}

//base64解密
+ (NSData *)base64DecodedDataWithString:(NSString *)string{
    if (string == nil || string == NULL) {
        return nil;
    }else if (![string isKindOfClass:[NSString class]]){
        return nil;
    }
    
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }
    
    NSDataBase64DecodingOptions options;
    options = NSDataBase64DecodingIgnoreUnknownCharacters;
    return [[NSData alloc] initWithBase64EncodedString:string options:options];;
}

//对字符串数据进行MD5的签名
+ (NSString *)md5SignWithString:(NSString *)string{
    const char *object = [string UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(object, (CC_LONG)strlen(object), result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < 16; i++) {
        [hash appendFormat:@"%02X",result[i]];
         
    }
    return [hash lowercaseString];
}

//对二进制数据进行MD5的签名
+ (NSData *)md5SignWithData:(NSData *)data{
    Byte byte[CC_MD5_DIGEST_LENGTH];   //定义一个字节数组来接收结果
    CC_MD5((const void*)([data bytes]), (CC_LONG)[data length], byte);
    return [NSData dataWithBytes:byte length:CC_MD5_DIGEST_LENGTH];
}


/**
*  AES128 + ECB + PKCS7
*  @param data 要加密的原始数据
*  @param key  加密 key
*  @return  加密后数据
*/
+ (NSData *)aesEncryptData:(NSData *)data key:(NSData *)key{
    //判断解密的数据流是否存在
    if (data == nil || data == NULL) {
        return nil;
    }else if (![data isKindOfClass:[NSData class]]){
        return nil;
    }else if ([data length] <= 0){
        return nil;
    }
    
    //判断解密的Key是否存在
    if (key == nil || key == NULL) {
        return nil;
    }else if (![key isKindOfClass:[NSData class]]){
        return nil;
    }else if ([key length] <= 0){
        return nil;
    }
    
    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];
    
    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    //do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus =
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode|kCCOptionPKCS7Padding, cKey, kCCKeySizeAES128, nil, [data bytes], [data length], buffer, bufferSize, &encryptedSize);
    
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
    }
    return result;
}

/**
*  AES128 + ECB + PKCS7
*  @param data 要解密的原始数据
*  @param key  解密 key
*  @return  解密后数据
*/
+ (NSData *)aesDecryptData:(NSData *)data key:(NSData *)key{
    //判断解密的流数据是否存在
    if (data == nil || data == NULL) {
        return nil;
    }else if (![data isKindOfClass:[NSData class]]){
        return nil;
    }else if ([data length] <= 0){
        return nil;
    }
    
    //判断解密的Key是否存在
    if (key == nil || key == NULL) {
        return nil;
    }else if (![key isKindOfClass:[NSData class]]){
        return nil;
    }else if ([key length] <= 0){
        return nil;
    }
    
    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];
    
    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    //do decrypt
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode|kCCOptionPKCS7Padding, cKey, kCCKeySizeAES128, nil, [data bytes], [data length], buffer, bufferSize, &decryptedSize);
    
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
    }
    return result;
}

@end
