module DNS.Protocol.DNSClass where

import qualified Data.Binary.Bits.Get as Bits
import qualified Data.Binary.Bits.Put as Bits
import           Protolude

import           Parsing.BinaryBit

-- | 'DNSClass'es have been little used but constitute another dimension of the DNS distributed database.
--   In particular, there is no necessary relationship between the namespace or root servers for one data 'DNSClass'
--   and those for another data 'DNSClass'.  The same 'DNSName' can have completely different meanings in different CLASSes.
data DNSClass = ClsInternet -- ^ RFC1035
              | ClsChaos    -- ^ D. Moon, "Chaosnet", A.I. Memo 628, June 1981.
              | ClsHesiod   -- ^ Project Athena Technical Plan - Name Service, April 1987
              | ClsNone     -- ^ RFC2136
              | ClsAny      -- ^ RFC1035
              deriving (Eq, Ord, Show)

instance BinaryPut DNSClass where
  bput x = Bits.putWord16be 16 $ case x of
    ClsInternet -> 0x0001
    ClsChaos    -> 0x0003
    ClsHesiod   -> 0x0004
    ClsNone     -> 0x00FE
    ClsAny      -> 0x00FF

instance BinaryGet DNSClass where
  bget = do
    cls <- Bits.getWord16be 16
    return $ case cls of
      0x0001 -> ClsInternet
      0x0003 -> ClsChaos
      0x0004 -> ClsHesiod
      0x00FE -> ClsNone
      0x00FF -> ClsAny
      _      -> panic $ "Unknown dns class received " <> show cls

instance BinaryBit DNSClass
