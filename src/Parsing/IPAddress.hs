module Parsing.IPAddress where

import           Data.Bits (shift, shiftR, (.&.))
import           Data.Word (Word32, Word8)
import           Protolude

ipAddress :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
ipAddress b1 b2 b3 b4 = foldl (\a b -> shift a 8 + fromIntegral b) (0 :: Word32) [b1,b2,b3,b4]

addressToOctets :: Word32 -> (Word8, Word8, Word8, Word8)
addressToOctets addr = (b1,b2,b3,b4)
    where b4 = fromIntegral $ addr .&. (2^(8 :: Integer) - 1)
          b3 = fromIntegral $ shiftR (addr .&. (2^(16 :: Integer) - 1)) 8
          b2 = fromIntegral $ shiftR (addr .&. (2^(24 :: Integer) - 1)) 16
          b1 = fromIntegral $ shiftR (addr .&. (2^(32 :: Integer) - 1)) 24

