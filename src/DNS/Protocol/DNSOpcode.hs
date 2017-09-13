module DNS.Protocol.DNSOpcode where

import qualified Data.Binary.Bits.Get as Bits
import qualified Data.Binary.Bits.Put as Bits
import           Protolude

import           Parsing.BinaryBit

-- | Specifies kind of query in this message. This value is set by the originator of a query and copied into
--   the response.
data OpCode
  = OpQuery   -- ^ RFC1035
  | OpIQuery  -- ^ RFC3425
  | OpStatus  -- ^ RFC1035
  | OpNotify  -- ^ RFC1996
  | OpUpdate  -- ^ RFC2136
  deriving (Eq, Ord, Show)

instance BinaryPut OpCode where
  bput x = Bits.putWord8 4 $ case x of
    OpQuery  -> 0
    OpIQuery -> 1
    OpStatus -> 2
    OpNotify -> 4
    OpUpdate -> 5

instance BinaryGet OpCode where
  bget = do
    op <- Bits.getWord8 4
    return $ case op of
      0 -> OpQuery
      1 -> OpIQuery
      2 -> OpStatus
      4 -> OpNotify
      5 -> OpUpdate
      _ -> panic $ "Unknown opcode received " <> show op

instance BinaryBit OpCode
