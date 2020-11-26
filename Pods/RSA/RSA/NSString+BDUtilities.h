//
//  Created by Patrick Hogan/Manuel Zamora 2012
//


////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark - Public Interface
////////////////////////////////////////////////////////////////////////////////////////////////////////////
#import <Foundation/Foundation.h>
#import "BDError.h"
#import "BDLog.h"
@interface NSString (BDUtilities)

+ (BOOL)isEmpty:(NSString *)string;

+ (NSString *)randomStringWithLength:(NSInteger)length;

- (BOOL)containsSubstring:(NSString *)substring;

@end
