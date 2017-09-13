{-# LANGUAGE RecordWildCards #-}
module DNS.Protocol.ResourceRecord where

import qualified Data.Binary.Bits.Get            as Bits
import qualified Data.Binary.Bits.Put            as Bits
import           Protolude

import           DNS.Protocol.DNSClass
import           DNS.Protocol.DNSName
import           DNS.Protocol.ResourceRecordType

import           Parsing.BinaryBit

-- | The answer, authority, and additional sections all share the same format: a variable number of resource records,
--   where the number of records is specified in the corresponding count field in the header.
data StdResourceRecord = StdResourceRecord
  { rrName   :: DNSName            -- ^ a domain name to which this resource record pertains.
  , rrType   :: ResourceRecordType -- ^ this field specifies the meaning of the data in the 'rrData' field.
  , rrClass  :: DNSClass           -- ^ specifies the class of the data in the 'rrData' field.
  , rrTTL    :: Word32             -- ^ specifies the time interval (in seconds) that the resource record may
                                   --   be cached before it should be discarded.
  , rrLength :: Word16             -- ^ specifies the length in octets of the 'rrData' field.
  , rrData   :: RData              -- ^ a variable length string that describes the resource.
  } deriving (Eq, Ord, Show)

instance BinaryGet StdResourceRecord where
  bget = do
    labels <- bget
    typ <- bget
    cls <- bget
    ttl <- Bits.getWord32be 32
    len <- Bits.getWord16be 16
    dat <- getRData typ
    return StdResourceRecord { rrName = labels
                          , rrType = typ
                          , rrClass = cls
                          , rrTTL = ttl
                          , rrLength = len
                          , rrData = dat
                          }

instance BinaryPut StdResourceRecord where
  bput StdResourceRecord {..} = do
    bput rrName
    bput rrType
    bput rrClass
    Bits.putWord32be 32 rrTTL
    Bits.putWord16be 16 rrLength
    bput rrData

instance BinaryBit StdResourceRecord

-- | Calculate the 'rrLength' field of a 'StdResourceRecord'
calculateRRLength :: StdResourceRecord -> StdResourceRecord
calculateRRLength rr = rr {rrLength = fromIntegral . byteSz $ rrData rr}

data OptResourceRecord = OptResourceRecord
  { rrOptName          :: DNSName
  , rrOptType          :: ResourceRecordType
  , rrOptPayloadSz     :: Word16
  , rrOptExtendedRCode :: Word32
  , rrOptLength        :: Word16
  , rrOptData          :: RData
  } deriving (Eq, Ord, Show)

instance BinaryGet OptResourceRecord where
  bget = do
    labels <- bget
    typ <- bget
    paysz <- Bits.getWord16be 16
    extrc <- Bits.getWord32be 32
    len <- Bits.getWord16be 16
    dat <- getRData typ
    return OptResourceRecord { rrOptName = labels
                             , rrOptType = typ
                             , rrOptPayloadSz = paysz
                             , rrOptExtendedRCode = extrc
                             , rrOptLength = len
                             , rrOptData = dat
                             }

instance BinaryPut OptResourceRecord where
  bput OptResourceRecord {..} = do
    bput rrOptName
    bput rrOptType
    Bits.putWord16be 16 rrOptPayloadSz
    Bits.putWord32be 32 rrOptExtendedRCode
    Bits.putWord16be 16 rrOptLength
    bput rrOptData

instance BinaryBit OptResourceRecord

data ResourceRecord = Std StdResourceRecord
                    | Opt OptResourceRecord
                    deriving (Eq, Ord, Show)

instance BinaryGet ResourceRecord where
  bget = do
    -- Look ahead for BitGet would be nicee :(
    name <- bget
    typ  <- bget
    case typ of
      RROPT -> do
        paysz <- Bits.getWord16be 16
        extrc <- Bits.getWord32be 32
        len   <- Bits.getWord16be 16
        dat   <- getRData typ
        return $ Opt OptResourceRecord { rrOptName = name
                                       , rrOptType = typ
                                       , rrOptPayloadSz = paysz
                                       , rrOptExtendedRCode = extrc
                                       , rrOptLength = len
                                       , rrOptData = dat
                                       }
      _ -> do
        cls <- bget
        ttl <- Bits.getWord32be 32
        len <- Bits.getWord16be 16
        dat <- getRData typ
        return $ Std StdResourceRecord { rrName = name
                                       , rrType = typ
                                       , rrClass = cls
                                       , rrTTL = ttl
                                       , rrLength = len
                                       , rrData = dat
                                       }

instance BinaryPut ResourceRecord where
  bput (Std x) = bput x
  bput (Opt x) = bput x

instance BinaryBit ResourceRecord

-- | A variable length string that describes the resource. The format of this information varies according to the
--   'ResourceRecordType' and 'DNSClass' of the resource record
data RData
  -- | A records cause no additional section processing. The 'rrData' section of an A line in a master
  --   file is an Internet address expressed as four decimal numbers separated by dots without any imbedded spaces
  = RDA Word32
  -- | A 'DNSName' which specifies the canonical or primary name for the owner. The owner name is an alias
  | RDCName { rdCNameName :: DNSName }
  -- | HINFO records are used to acquire general information about a host. The main use is for protocols such as
  --   FTP that can use special procedures when talking between machines or operating systems of the same type.
  | RDHInfo { rdHInfoCpu :: DNSLabel, rdHInfoOS :: DNSLabel }
  -- | MX records cause type A additional section processing for the host specified by EXCHANGE. The use of
  --   MX RRs is explained in detail in (RFC974)
  | RDMX Word16 DNSName
  | RDSOA DNSName DNSName Word32 Word32 Word32 Word32 Word32
  | RDOpt Word16 Word16 [Word8]
  deriving (Eq, Ord, Show)

instance BinaryPut RData where
  bput (RDA a)      = Bits.putWord32be 32 a
  bput (RDCName cn) = bput cn
  bput (RDHInfo cpu os) = do
    bput cpu
    bput os
  bput (RDMX pref xchg) = do
    Bits.putWord16be 16 pref
    bput xchg
  bput (RDSOA mname rname serial refresh retry' expire minm) = do
    bput mname
    bput rname
    Bits.putWord32be 32 serial
    Bits.putWord32be 32 refresh
    Bits.putWord32be 32 retry'
    Bits.putWord32be 32 expire
    Bits.putWord32be 32 minm
  bput (RDOpt code len octs) = do
    Bits.putWord16be 16 code
    Bits.putWord16be 16 len
    forM_ octs $ Bits.putWord8 8

-- | Treat stream as a specific 'RData' given a 'ResourceRecordType'
getRData :: ResourceRecordType -> Bits.BitGet RData
getRData typ =
  case typ of
    RRA     -> RDA <$> Bits.getWord32be 32
    RRCNAME -> RDCName <$> bget
    RRHINFO -> RDHInfo <$> bget <*> bget
    RRMX    -> do
      pref <- Bits.getWord16be 16
      xchg <- bget
      return $ RDMX pref xchg
    RRSOA   -> do
      mname   <- bget
      rname   <- bget
      serial  <- Bits.getWord32be 32
      refresh <- Bits.getWord32be 32
      retry'  <- Bits.getWord32be 32
      expire  <- Bits.getWord32be 32
      minm    <- Bits.getWord32be 32
      return $ RDSOA mname rname serial refresh retry' expire minm
    RROPT    -> do
      code <- Bits.getWord16be 16
      len  <- Bits.getWord16be 16
      octs <- replicateM (fromIntegral len) $ Bits.getWord8 8
      return $ RDOpt code len octs
    _    -> panic $ "Unsupported RDATA type " <> show typ

instance BinarySize RData where
  byteSz (RDA _)                       = 4
  byteSz (RDCName name)                = byteSz name
  byteSz (RDHInfo os cpu)              = byteSz os + byteSz cpu
  byteSz (RDMX _ chg)                  = 2 + byteSz chg
  byteSz (RDSOA mname rname _ _ _ _ _) = 20 + byteSz mname + byteSz rname
  byteSz (RDOpt _ _ els)               = 4 + length els

