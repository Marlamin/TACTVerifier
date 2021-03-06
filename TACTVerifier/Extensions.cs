﻿using System;
using System.IO;

namespace TACTVerifier
{
    public static class ByteArrayExtensions
    {
        public static string ToHexString(this byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
    }

    public static class BinaryReaderExtensions
    {
        public static double ReadDouble(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToDouble(reader.ReadInvertedBytes(8), 0);
            }

            return reader.ReadDouble();
        }

        public static Int16 ReadInt16(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToInt16(reader.ReadInvertedBytes(2), 0);
            }

            return reader.ReadInt16();
        }

        public static Int32 ReadInt32(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToInt32(reader.ReadInvertedBytes(4), 0);
            }

            return reader.ReadInt32();
        }

        public static Int64 ReadInt64(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToInt64(reader.ReadInvertedBytes(8), 0);
            }

            return reader.ReadInt64();
        }

        public static Single ReadSingle(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToSingle(reader.ReadInvertedBytes(4), 0);
            }

            return reader.ReadSingle();
        }

        public static UInt16 ReadUInt16(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToUInt16(reader.ReadInvertedBytes(2), 0);
            }

            return reader.ReadUInt16();
        }

        public static UInt32 ReadUInt32(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToUInt32(reader.ReadInvertedBytes(4), 0);
            }

            return reader.ReadUInt32();
        }

        public static UInt64 ReadUInt64(this BinaryReader reader, bool invertEndian = false)
        {
            if (invertEndian)
            {
                return BitConverter.ToUInt64(reader.ReadInvertedBytes(8), 0);
            }

            return reader.ReadUInt64();
        }

        public static long ReadInt40BE(this BinaryReader reader)
        {
            byte[] val = reader.ReadBytes(5);
            return val[4] | val[3] << 8 | val[2] << 16 | val[1] << 24 | val[0] << 32;
        }

        public static UInt64 ReadUInt40(this BinaryReader reader, bool invertEndian = false)
        {
            ulong b1 = reader.ReadByte();
            ulong b2 = reader.ReadByte();
            ulong b3 = reader.ReadByte();
            ulong b4 = reader.ReadByte();
            ulong b5 = reader.ReadByte();

            if (invertEndian)
            {
                return (ulong)(b1 << 32 | b2 << 24 | b3 << 16 | b4 << 8 | b5);
            }
            else
            {
                return (ulong)(b5 << 32 | b4 << 24 | b3 << 16 | b2 << 8 | b1);
            }
        }

        private static byte[] ReadInvertedBytes(this BinaryReader reader, int byteCount)
        {
            byte[] byteArray = reader.ReadBytes(byteCount);
            Array.Reverse(byteArray);

            return byteArray;
        }
    }
}
