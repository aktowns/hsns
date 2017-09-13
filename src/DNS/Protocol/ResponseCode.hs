module DNS.Protocol.ResponseCode where

import           Protolude

import qualified Data.Binary.Bits.Get as Bits
import qualified Data.Binary.Bits.Put as Bits
import           Parsing.BinaryBit

-- | Response code - this 4 bit field is set as part of responses.
data RCode
  = RCNoError     -- ^ No Error                           (RFC1035)
  | RCFormErr     -- ^ Format Error                       (RFC1035)
  | RCServFail    -- ^ Server Failure                     (RFC1035)
  | RCNXDomain    -- ^ Non-Existent Domain                (RFC1035)
  | RCNotImp      -- ^ Not Implemented                    (RFC1035)
  | RCRefused     -- ^ Query Refused                      (RFC1035)
  | RCYXDomain    -- ^ Name Exists when it should not	    (RFC2136, RFC6672)
  | RCYXRRSet     -- ^ RR Set Exists when it should not	  (RFC2136)
  | RCNXRRSet     -- ^ RR Set that should exist does not	(RFC2136)
  | RCNotAuth     -- ^ Not Authorized	                    (RFC2845)
  | RCNotZone     -- ^ Name not contained in zone	        (RFC2136)
  | RCBadSig      -- ^ TSIG Signature Failure	            (RFC2845)
  | RCBadKey      -- ^ Key not recognized	                (RFC2845)
  | RCBadTime     -- ^ Signature out of time window	      (RFC2845)
  | RCBadMode     -- ^ Bad TKEY Mode	                    (RFC2930)
  | RCBadName     -- ^ Duplicate key name	                (RFC2930)
  | RCBadAlg      -- ^ Algorithm not supported	          (RFC2930)
  | RCBadTrunc    -- ^ Bad Truncation	                    (RFC4635)
  | RCBadCookie   -- ^ Bad/missing Server Cookie	        (RFC7873)
  deriving (Eq, Ord, Show)

instance BinaryPut RCode where
  bput x = Bits.putWord8 4 $ case x of
    RCNoError   -> 0
    RCFormErr   -> 1
    RCServFail  -> 2
    RCNXDomain  -> 3
    RCNotImp    -> 4
    RCRefused   -> 5
    RCYXDomain  -> 6
    RCYXRRSet   -> 7
    RCNXRRSet   -> 8
    RCNotAuth   -> 9
    RCNotZone   -> 10
    RCBadSig    -> 16
    RCBadKey    -> 17
    RCBadTime   -> 18
    RCBadMode   -> 19
    RCBadName   -> 20
    RCBadAlg    -> 21
    RCBadTrunc  -> 22
    RCBadCookie -> 23

instance BinaryGet RCode where
  bget = do
    code <- Bits.getWord8 4
    return $ case code of
      0  -> RCNoError
      1  -> RCFormErr
      2  -> RCServFail
      3  -> RCNXDomain
      4  -> RCNotImp
      5  -> RCRefused
      6  -> RCYXDomain
      7  -> RCYXRRSet
      8  -> RCNXRRSet
      9  -> RCNotAuth
      10 -> RCNotZone
      16 -> RCBadSig
      17 -> RCBadKey
      18 -> RCBadTime
      19 -> RCBadMode
      20 -> RCBadName
      21 -> RCBadAlg
      22 -> RCBadTrunc
      23 -> RCBadCookie
      _  -> panic $ "Unknown RCode received " <> show code

instance BinaryBit RCode