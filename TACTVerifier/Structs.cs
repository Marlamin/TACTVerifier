namespace TACTVerifier
{
    public struct IndexEntry
    {
        public uint offset;
        public uint size;
    }

    public struct IndexFooter
    {
        public byte[] tocHash;
        public byte version;
        public byte unk0;
        public byte unk1;
        public byte blockSizeKB;
        public byte offsetBytes;
        public byte sizeBytes;
        public byte keySizeInBytes;
        public byte checksumSize;
        public uint numEntries;
        public byte[] footerChecksum;
    }

    public struct BLTEChunkInfo
    {
        public bool isFullChunk;
        public int inFileSize;
        public int actualSize;
        public byte[] checkSum;
        public char mode;
    }
}
