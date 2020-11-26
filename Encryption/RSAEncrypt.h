//
//  RSAEncrypt.h
//  Encryption
//
//  Created by Civet on 2020/11/24.
//  Copyright © 2020 PersonalONBYL. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAEncrypt : NSObject

+ (NSString *)encryptString:(NSString *)originString publicKey:(NSString *)publicKey;

+ (NSString *)decryptString:(NSString *)encryptString privateKey:(NSString *)privateKey;

@end

NS_ASSUME_NONNULL_END
