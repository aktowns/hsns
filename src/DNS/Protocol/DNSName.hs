module DNS.Protocol.DNSName where

import           Control.Monad.Loops   (whileJust)
import qualified Data.Binary.Bits.Get  as Bits
import qualified Data.Binary.Bits.Put  as Bits
import qualified Data.ByteString.Char8 as BS
import           Protolude

import           Parsing.BinaryBit

-- | Labels must follow the rules for ARPANET host names. They must start with a letter, end with a letter or digit,
--   and have as interior characters only letters, digits, and hyphen.  There are also some restrictions on the length.
--   Labels must be 63 characters or less.
--
--   Each label is represented as a one octet length field followed by that number of octets. Since every domain name
--   ends with the null label of the root, a domain name is terminated by a length byte of zero.
newtype DNSLabel = DNSLabel BS.ByteString deriving (Eq, Ord, Show)

instance BinaryPut DNSLabel where
  bput (DNSLabel l) = do
    let len = BS.length l
    Bits.putWord8 8 (fromIntegral len)
    Bits.putByteString l

instance BinaryGet DNSLabel where
  bget = do
    len <- Bits.getWord8 8
    case len of
      0x00 -> return $ DNSLabel BS.empty
      _    -> DNSLabel <$> Bits.getByteString (fromIntegral len)

instance BinaryBit DNSLabel

-- | Is it the end of a set of labels (0x00)
nullLabel :: DNSLabel -> Bool
nullLabel (DNSLabel x) = BS.null x

-- | Make a 'DNSLabel' from a 'String'
mkLabelFromStr :: Text -> DNSLabel
mkLabelFromStr s = DNSLabel $ toS s

instance BinarySize DNSLabel where
  byteSz (DNSLabel l) = BS.length l + 1

-- | 'DNSName' is an owner name, i.e., the name of the node to which this resource record pertains. 'DNSName's are
--   specific to a 'DNSClass'.  'DNSName's consist of an ordered sequence of one or more 'DNSLabel's.
newtype DNSName = DNSName { nameComponents :: [DNSLabel] } deriving (Show, Eq, Ord)

-- | Make a 'DNSName' given a dotted form name eg, "ashleytowns.id.au"
mkDNSNameFromStr :: Text -> DNSName
mkDNSNameFromStr str = DNSName $ map DNSLabel $ BS.split '.' $ toS str

instance BinaryPut DNSName where
  bput (DNSName x) = do
    forM_ x bput
    Bits.putWord8 8 0x00

instance BinaryGet DNSName where
  bget = DNSName <$> whileJust readLabel return
    where
      readLabel :: Bits.BitGet (Maybe DNSLabel)
      readLabel = do
        label <- bget
        return $ if nullLabel label then Nothing else Just label

instance BinaryBit DNSName

instance BinarySize DNSName where
  byteSz (DNSName els) = fromIntegral $ foldl (\acc e -> acc + byteSz e) 1 els
