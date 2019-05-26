using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

namespace TACTVerifier
{
    class Program
    {
        private static List<string> archives = new List<string>();

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                throw new ArgumentOutOfRangeException("Requires one argument: directory to verify contents of");
            }

            /* CONFIGS */
            Console.WriteLine("Listing configs..");
            var allConfigs = Directory.GetFiles(Path.Combine(args[0], "tpr", "wow", "config"), "*", SearchOption.AllDirectories);
            var configCount = allConfigs.Length;

            Console.Write("Checking configs: ");

            for (var i = 0; i < configCount; i++)
            {
                Console.Write("\rChecking configs: " + (i + 1) + "/" + configCount);

                var file = allConfigs[i];
                using (var hasher = MD5.Create())
                {
                    var filename = Path.GetFileNameWithoutExtension(file).ToUpper();
                    var md5sum = hasher.ComputeHash(File.ReadAllBytes(file)).ToHexString();
                    if (md5sum != filename)
                    {
                        Console.WriteLine(" !!! MD5 sum " + md5sum + " does not match " + filename);
                    }
                }

            }
            Console.WriteLine("\nDone checking configs!");

            /* INDEX/ARCHIVES */
            Console.WriteLine("Listing indices..");
            var allIndices = Directory.GetFiles(Path.Combine(args[0], "tpr", "wow", "data"), "*.index", SearchOption.AllDirectories);
            var indexCount = allIndices.Length;

            Console.Write("Checking archives and indices: ");
            for (var i = 0; i < indexCount; i++)
            {
                Console.Write("\rChecking archives and indices: " + (i + 1) + "/" + indexCount);
                var index = allIndices[i];

                // Add to archive list so data loop below doesn't check it
                archives.Add(Path.GetFileNameWithoutExtension(index));

                // READ & CHECK INDEX
                var indexEntries = new Dictionary<string, IndexEntry>();
                using (var stream = new FileStream(index, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var bin = new BinaryReader(stream))
                {
                    bin.BaseStream.Position = bin.BaseStream.Length - 28;
                    var footer = new IndexFooter
                    {
                        tocHash = bin.ReadBytes(8),
                        version = bin.ReadByte(),
                        unk0 = bin.ReadByte(),
                        unk1 = bin.ReadByte(),
                        blockSizeKB = bin.ReadByte(),
                        offsetBytes = bin.ReadByte(),
                        sizeBytes = bin.ReadByte(),
                        keySizeInBytes = bin.ReadByte(),
                        checksumSize = bin.ReadByte(),
                        numEntries = bin.ReadUInt32()
                    };

                    // Is this check ridiculous? I feel like it is.
                    if ((footer.numEntries & 0xff000000) != 0)
                    {
                        Console.WriteLine(footer.numEntries + " seems wrong, reading as BE instead!");
                        bin.BaseStream.Position -= 4;
                        footer.numEntries = bin.ReadUInt32(true);
                    }

                    // Check for unexpected values
                    if (footer.version != 1) Console.WriteLine("\nUnexpected index version " + footer.version + " for " + index);
                    if (footer.blockSizeKB != 4) Console.WriteLine("\nUnexpected blockSizeKB " + footer.blockSizeKB + " for " + index);
                    if (footer.sizeBytes != 4) Console.WriteLine("\nUnexpected sizeBytes " + footer.sizeBytes + " for " + index);
                    if (footer.offsetBytes != 0 && footer.offsetBytes != 4 && footer.offsetBytes != 5 && footer.offsetBytes != 6) Console.WriteLine("\nUnexpected offsetBytes " + footer.offsetBytes + " for " + index);
                    if (footer.keySizeInBytes != 16) Console.WriteLine("\nUnexpected keySizeBytes " + footer.keySizeInBytes + " for " + index);
                    if (footer.checksumSize != 8) Console.WriteLine("\nUnexpected checksumSize " + footer.checksumSize + " for " + index);

                    // Check footer MD5
                    var footerMD5 = bin.ReadBytes(8);

                    bin.BaseStream.Position = bin.BaseStream.Length - 20;
                    var footerBytes = bin.ReadBytes(20);
                    for (var j = 12; j < 20; j++)
                    {
                        footerBytes[j] = 0;
                    }

                    using (var hasher = MD5.Create())
                    {
                        var md5sum = hasher.ComputeHash(footerBytes).ToHexString().Substring(0, 16);
                        if (md5sum != footerMD5.ToHexString())
                        {
                            Console.WriteLine(" !!! MD5 sum " + md5sum + " does not match " + footerMD5.ToHexString() + " in file " + index);
                        }
                    }

                    // Go back to start of index to read blocks etc
                    bin.BaseStream.Position = 0;

                    var indexBlockSize = 1024 * footer.blockSizeKB;

                    int indexEntryCount = (int)bin.BaseStream.Length / indexBlockSize;
                    var recordSize = footer.keySizeInBytes + footer.sizeBytes + footer.offsetBytes;
                    var recordsPerBlock = indexBlockSize / recordSize;
                    var blockPadding = indexBlockSize - (recordsPerBlock * recordSize);

                    var addedEntries = 0;

                    for (var b = 0; b < indexEntryCount; b++)
                    {
                        for (var bi = 0; bi < recordsPerBlock; bi++)
                        {
                            var encodingKey = bin.ReadBytes(footer.keySizeInBytes).ToHexString();

                            var entry = new IndexEntry();

                            if (footer.sizeBytes == 4)
                            {
                                entry.size = bin.ReadUInt32(true);
                            }
                            else
                            {
                                throw new NotImplementedException("Index size reading other than 4 is not implemented!");
                            }

                            if (footer.offsetBytes == 4)
                            {
                                // Archive index
                                entry.offset = bin.ReadUInt32(true);
                            }
                            else if (footer.offsetBytes == 5)
                            {
                                // Patch group index
                                bin.ReadBytes(5);
                            }
                            else if (footer.offsetBytes == 6)
                            {
                                // Group index
                                bin.ReadBytes(6);
                            }
                            else
                            {
                                // File index
                            }

                            if (entry.size != 0)
                            {
                                if (!indexEntries.ContainsKey(encodingKey))
                                {
                                    if (addedEntries != footer.numEntries)
                                    {
                                        indexEntries.Add(encodingKey, entry);
                                        addedEntries++;
                                    }
                                    else
                                    {
                                        Console.WriteLine("Skipping " + encodingKey + " ending at " + bin.BaseStream.Position + " as we've read all entries!");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("Index " + Path.GetFileName(index) + " (" + footer.offsetBytes + ") contains duplicate ekey " + encodingKey);
                                }
                            }
                        }

                        bin.ReadBytes(blockPadding);
                    }
                }

                var sortedIndexList = indexEntries.ToList();
                sortedIndexList.Sort((pair1, pair2) => pair1.Value.offset.CompareTo(pair2.Value.offset));
                // TODO: READ & CHECK ARCHIVE
                var archiveName = index.Replace(".index", "");
                if (File.Exists(archiveName))
                {
                    using (var stream = new FileStream(archiveName, FileMode.Open, FileAccess.Read, FileShare.Read))
                    using (var bin = new BinaryReader(stream))
                    {
                        foreach (var entry in sortedIndexList)
                        {
                            if (bin.BaseStream.Position != entry.Value.offset)
                            {
                                Console.WriteLine("Seeking to " + entry.Value.offset + " and reading " + entry.Value.size);
                                bin.BaseStream.Position = entry.Value.offset;
                            }
                            bin.ReadBytes((int)entry.Value.size);
                        }
                    }
                }
            }
            Console.WriteLine("\nDone checking indices!");

            /* DATA */
            Console.WriteLine("Listing data..");
            var allData = Directory.GetFiles(Path.Combine(args[0], "tpr", "wow", "data"), "*", SearchOption.AllDirectories);
            var dataCount = allData.Length;

            Console.Write("Checking data: ");
            for (var i = 0; i < dataCount; i++)
            {
                Console.Write("\rChecking data: " + (i + 1) + "/" + dataCount);

                var file = allData[i];
                if (file.EndsWith(".index")) continue;
                if (archives.Contains(Path.GetFileNameWithoutExtension(file))) continue;

                using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var bin = new BinaryReader(stream))
                {
                    try
                    {
                        var header = bin.ReadUInt32();
                        if (header != 0x45544C42)
                        {
                            Console.WriteLine(" Invalid BLTE file! " + header + ": " + file);
                            if (header == 0x4453425A)
                            {
                                Console.WriteLine(" File is a patch archive!");
                            }
                            else if (header == 268583248)
                            {
                                Console.WriteLine(" File is a patch index!");
                            }
                            else if (header == 893668643 || header == 1279870499)
                            {
                                Console.WriteLine(" File is Overwatch root file!");
                            }
                            else
                            {
                                Console.WriteLine("Unknown file encountered!");
                                Console.ReadLine();
                            }
                        }
                        else
                        {
                            var blteSize = bin.ReadUInt32(true);

                            BLTEChunkInfo[] chunkInfos;

                            if (blteSize == 0)
                            {
                                chunkInfos = new BLTEChunkInfo[1];
                                chunkInfos[0].isFullChunk = false;
                                chunkInfos[0].inFileSize = Convert.ToInt32(bin.BaseStream.Length - bin.BaseStream.Position);
                                chunkInfos[0].actualSize = Convert.ToInt32(bin.BaseStream.Length - bin.BaseStream.Position);
                                chunkInfos[0].checkSum = new byte[16];

                                using (var hasher = MD5.Create())
                                {
                                    var filename = Path.GetFileNameWithoutExtension(file).ToUpper();
                                    var md5sum = hasher.ComputeHash(File.ReadAllBytes(file)).ToHexString();
                                    if (md5sum != filename)
                                    {
                                        Console.WriteLine(" !!! MD5 sum " + md5sum + " does not match " + filename);
                                    }
                                }
                            }
                            else
                            {

                                var bytes = bin.ReadBytes(4);

                                //Code by TOM_RUS 
                                //Retrieved from https://github.com/WoW-Tools/CASCExplorer/blob/cli/CascLib/BLTEHandler.cs#L76

                                var chunkCount = bytes[1] << 16 | bytes[2] << 8 | bytes[3] << 0;

                                var supposedHeaderSize = 24 * chunkCount + 12;

                                if (supposedHeaderSize != blteSize)
                                {
                                    File.AppendAllText("bad.txt", file + " (Invalid header size) " + Environment.NewLine);
                                }

                                if (supposedHeaderSize > bin.BaseStream.Length)
                                {
                                    File.AppendAllText("bad.txt", file + " (Not enough data) " + Environment.NewLine);
                                }

                                chunkInfos = new BLTEChunkInfo[chunkCount];

                                for (var j = 0; j < chunkCount; j++)
                                {
                                    chunkInfos[j].isFullChunk = true;
                                    chunkInfos[j].inFileSize = bin.ReadInt32(true);
                                    chunkInfos[j].actualSize = bin.ReadInt32(true);
                                    chunkInfos[j].checkSum = new byte[16];
                                    chunkInfos[j].checkSum = bin.ReadBytes(16);
                                }

                                foreach (var chunk in chunkInfos)
                                {
                                    using (var chunkResult = new MemoryStream())
                                    {
                                        if (chunk.inFileSize > bin.BaseStream.Length)
                                        {
                                            File.AppendAllText("bad.txt", file + " (Not enough data remaining in stream) " + Environment.NewLine);
                                            continue;
                                        }

                                        var chunkBuffer = bin.ReadBytes(chunk.inFileSize);

                                        using (var hasher = MD5.Create())
                                        {
                                            var md5sum = hasher.ComputeHash(chunkBuffer);

                                            if (chunk.isFullChunk && BitConverter.ToString(md5sum) != BitConverter.ToString(chunk.checkSum))
                                            {
                                                File.AppendAllText("bad.txt", file + " (chunk md5sum mismatch) " + Environment.NewLine);
                                                chunkBuffer = null;
                                                continue;
                                            }
                                        }

                                        using (var chunkms = new MemoryStream(chunkBuffer))
                                        using (var chunkreader = new BinaryReader(chunkms))
                                        {
                                            var mode = chunkreader.ReadChar();
                                            switch (mode)
                                            {
                                                case 'N': // none
                                                    chunkResult.Write(chunkreader.ReadBytes(chunk.actualSize), 0, chunk.actualSize); //read actual size because we already read the N from chunkreader
                                                    break;
                                                case 'Z': // zlib, todo
                                                    using (var mstream = new MemoryStream(chunkreader.ReadBytes(chunk.inFileSize - 1), 2, chunk.inFileSize - 3))
                                                    using (var ds = new DeflateStream(mstream, CompressionMode.Decompress))
                                                    {
                                                        ds.CopyTo(chunkResult);
                                                    }
                                                    break;
                                                case 'E': // encrypted
                                                          //Console.WriteLine("Encrypted file!");
                                                    break;
                                                case 'F': // frame
                                                default:
                                                    throw new Exception("Unsupported mode!");
                                            }

                                            // Don't check integrity for unsupported chunks
                                            if (mode == 'N' || mode == 'Z')
                                            {
                                                var chunkres = chunkResult.ToArray();
                                                if (chunk.isFullChunk && chunkres.Length != chunk.actualSize)
                                                {
                                                    File.AppendAllText("bad.txt", file + " (bad chunk result size) " + Environment.NewLine);
                                                }
                                                chunkres = null;
                                            }
                                            chunkBuffer = null;
                                        }
                                    }
                                }
                                chunkInfos = null;
                            }
                        }
                    }
                    catch (EndOfStreamException e)
                    {
                        Console.WriteLine(e.Message);
                        File.AppendAllText("bad.txt", file + Environment.NewLine);
                    }
                }
            }
            Console.WriteLine("\nDone checking data!");
        }
    }
}
