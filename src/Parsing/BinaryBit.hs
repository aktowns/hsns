module Parsing.BinaryBit where

import           Data.Binary.Bits.Get
import           Data.Binary.Bits.Put
import           Data.Binary.Get      (Get)
import           Data.Binary.Put      (Put)
import           Protolude

-- | wrapper around BitGet a
class BinaryGet a where
  -- | Parse and deserialize 'a'
  bget :: BitGet a

-- | wrapper around BitPut ()
class BinaryPut a where
  -- | serialize 'a'
  bput :: a -> BitPut ()

-- | Wrapper around BitGet and BitPut
class (BinaryGet a, BinaryPut a) => BinaryBit a where
  runBinGet :: Get a
  runBinGet = runBitGet bget

  runBinPut :: a -> Put
  runBinPut = runBitPut . bput

class BinarySize a where
  byteSz :: a -> Int
