using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Runtime.Remoting.Messaging;

namespace FF16_Pac
{
    public struct FF16_ArchiveEntry
    {
        //public ulong HeaderEntryUnknown1_UINT64;
        public uint HeaderEntryUnknown1_1_UINT32;
        public uint HeaderEntryUnknown1_2_UINT32;

        public ulong HeaderEntryUnknown2_UINT64; //This might potentially be the file size
        public ulong HeaderEntryUnknown3_UINT64; //This might potentially be the file offset data start
        public ulong HeaderEntryUnknown4_UINT64; //(IGNORE) Not sure but this value matches a value in the header HeaderUnknown2_UINT64
        public ulong HeaderEntry_OffsetIntoEncryptedFilePaths; //confirmed

        public uint HeaderEntryUnknown6_1_UINT32;
        public uint HeaderEntryUnknown6_2_UINT32;

        public ulong HeaderEntryUnknown7_UINT64;

        public string NOT_SERIALIZED_filePath;

        //EACH ENTRY IS SUPPSOEDLY 56 BYTES LONG
        public FF16_ArchiveEntry(BinaryReader reader)
        {
            //HeaderEntryUnknown1_UINT64 = reader.ReadUInt64();
            HeaderEntryUnknown1_1_UINT32 = reader.ReadUInt32();
            HeaderEntryUnknown1_2_UINT32 = reader.ReadUInt32();

            HeaderEntryUnknown2_UINT64 = reader.ReadUInt64();
            HeaderEntryUnknown3_UINT64 = reader.ReadUInt64(); //uint64 offsetOfContent
            HeaderEntryUnknown4_UINT64 = reader.ReadUInt64(); //(IGNORE) Not sure but this value matches a value in the header HeaderUnknown2_UINT64
            HeaderEntry_OffsetIntoEncryptedFilePaths = reader.ReadUInt64();

            //HeaderEntryUnknown6_UINT64 = reader.ReadUInt64();
            HeaderEntryUnknown6_1_UINT32 = reader.ReadUInt32();
            HeaderEntryUnknown6_2_UINT32 = reader.ReadUInt32();

            HeaderEntryUnknown7_UINT64 = reader.ReadUInt64();

            NOT_SERIALIZED_filePath = "";
        }
    }

    public struct FF16_Archive
    {
        public ulong TotalFileSize;

        public uint HeaderMagic; //OFFSET 0
        public uint HeaderArchiveFileDataStartOffset_UINT32; //OFFSET 4
        public uint HeaderFileCount_UINT32; //OFFSET 8
        public uint HeaderUnknown1_UINT32; //OFFSET 12
        public ulong HeaderArchiveFileSize_UINT64; //OFFSET 16
        public ulong[] HeaderEncryptedPadding_UINT64s;
        public ulong HeaderUnknown2_UINT64; //(IGNORE) Not sure but this value matches a value in HeaderEntryUnknown4_UINT64
        public ulong HeaderEncryptedFilePathsStartOffset_UINT64;
        public ulong HeaderEncryptedFilePathsSize_UINT64;
        public byte[] HeaderBytePaddingData;
        public FF16_ArchiveEntry[] HeaderArchiveEntries;
        public byte[] HeaderEncryptedFilePaths;

        //public string NOT_SERIALIZED_HeaderFilePathsString;
        public string[] NOT_SERIALIZED_HeaderFilePaths;

        public void UnencryptFilePaths()
        {
            byte[] NOT_SERIALIZED_HeaderUnencryptedFilePaths = new byte[HeaderEncryptedFilePaths.Length];

            int encryptionKeyByteIndex = 0;

            for (int i = 0; i < HeaderEncryptedFilePaths.Length; i++)
            {
                byte[] keyAsBytes = BitConverter.GetBytes(HeaderEncryptedPadding_UINT64s[4]);

                byte originalByte = HeaderEncryptedFilePaths[i];
                byte xor = (byte)(keyAsBytes[encryptionKeyByteIndex] ^ originalByte);
                NOT_SERIALIZED_HeaderUnencryptedFilePaths[i] = xor;

                encryptionKeyByteIndex = (encryptionKeyByteIndex + 1) % 8;
            }

            //HeaderFilePathsString_NOT_SERIALIZED = Encoding.UTF8.GetString(HeaderUnencryptedFilePaths_NOT_SERIALIZED).Split('\0');
            NOT_SERIALIZED_HeaderFilePaths = Encoding.UTF8.GetString(NOT_SERIALIZED_HeaderUnencryptedFilePaths).Split('\0');
        }

        public void GetFilePaths()
        {
            for (int i = 0; i < HeaderArchiveEntries.Length; i++)
            {
                /*
                ulong arrayIndexStart = HeaderArchiveEntries[j].HeaderEntry_OffsetIntoEncryptedFilePaths - HeaderEncryptedFilePathsStartOffset_UINT64;
                int encryptionKeyByteIndex = 0;
                List<byte> NOT_SERIALIZED_HeaderUnencryptedFilePaths = new List<byte>();

                for (ulong j = 0; j < 256; j++)
                {
                    byte[] keyAsBytes = BitConverter.GetBytes(HeaderEncryptedPadding_UINT64s[4]);

                    byte originalByte = HeaderEncryptedFilePaths[arrayIndexStart + j];
                    byte xor = (byte)(keyAsBytes[encryptionKeyByteIndex] ^ originalByte);
                    NOT_SERIALIZED_HeaderUnencryptedFilePaths.Add(xor);

                    encryptionKeyByteIndex = (encryptionKeyByteIndex + 1) % 8;

                    string stringTest = Encoding.UTF8.GetString(NOT_SERIALIZED_HeaderUnencryptedFilePaths.ToArray());

                    if (stringTest.Contains('\0'))
                        break;
                    else
                    {
                        HeaderArchiveEntries[j].NOT_SERIALIZED_filePath = stringTest;
                    }
                }

                Console.WriteLine(HeaderArchiveEntries[j].NOT_SERIALIZED_filePath);
                */

                /*
                int encryptionKeyByteIndex = 0;
                byte[] NOT_SERIALIZED_HeaderUnencryptedFilePaths = new byte[HeaderEncryptedFilePaths.Length];

                for (ulong j = HeaderArchiveEntries[i].HeaderEntry_OffsetIntoEncryptedFilePaths - HeaderEncryptedFilePathsStartOffset_UINT64; (int)j < HeaderEncryptedFilePaths.Length; j++)
                {
                    byte[] keyAsBytes = BitConverter.GetBytes(HeaderEncryptedPadding_UINT64s[4]);

                    byte originalByte = HeaderEncryptedFilePaths[i];
                    byte xor = (byte)(keyAsBytes[encryptionKeyByteIndex] ^ originalByte);
                    NOT_SERIALIZED_HeaderUnencryptedFilePaths[i] = xor;

                    encryptionKeyByteIndex = (encryptionKeyByteIndex + 1) % 8;
                }

                HeaderArchiveEntries[i].NOT_SERIALIZED_filePath = Encoding.UTF8.GetString(NOT_SERIALIZED_HeaderUnencryptedFilePaths).Split('\0')[0];

                Console.WriteLine(HeaderArchiveEntries[i].NOT_SERIALIZED_filePath);
                */

                HeaderArchiveEntries[i].NOT_SERIALIZED_filePath = NOT_SERIALIZED_HeaderFilePaths[i];
            }
        }

        public void ExtractFiles(BinaryReader reader, string writeBasePath)
        {
            for (int i = 0; i < HeaderArchiveEntries.Length; i++)
            {
                FF16_ArchiveEntry entry = HeaderArchiveEntries[i];

                reader.BaseStream.Seek((long)entry.HeaderEntryUnknown3_UINT64, SeekOrigin.Begin);
                string finalFolderPath = writeBasePath + Path.GetDirectoryName(entry.NOT_SERIALIZED_filePath);
                string finalFilePath = writeBasePath + entry.NOT_SERIALIZED_filePath;

                if(Directory.Exists(finalFolderPath) == false)
                    Directory.CreateDirectory(finalFolderPath);

                if (File.Exists(finalFilePath))
                    File.Delete(finalFilePath);

                try
                {
                    using (var stream = new FileStream(finalFilePath, FileMode.CreateNew))
                    {
                        for (ulong y = 0; y < entry.HeaderEntryUnknown2_UINT64; y++)
                        {
                            try
                            {
                                stream.WriteByte(reader.ReadByte());
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("ERROR! {0}", e.Message);
                                break;
                            }
                        }
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine("ERROR! {0}", e.Message);
                }

                Console.WriteLine("Extracting ({0}/{1})... {2}", i, HeaderArchiveEntries.Length, entry.NOT_SERIALIZED_filePath);
            }
        }

        public FF16_Archive(string pacFilePath)
        {
            FileInfo fileInfo = new FileInfo(pacFilePath);
            TotalFileSize = (ulong)fileInfo.Length;

            using (BinaryReader reader = new BinaryReader(File.OpenRead(pacFilePath)))
            {
                //Joschka header
                HeaderMagic = reader.ReadUInt32(); //offset 0
                HeaderArchiveFileDataStartOffset_UINT32 = reader.ReadUInt32(); //offset 4
                HeaderFileCount_UINT32 = reader.ReadUInt32(); //offset 8
                HeaderUnknown1_UINT32 = reader.ReadUInt32(); //offset 12
                HeaderArchiveFileSize_UINT64 = reader.ReadUInt64(); //offset 16

                Console.WriteLine("HeaderMagic: [{0} BYTES] {1}", Marshal.SizeOf(HeaderMagic), HeaderMagic);
                Console.WriteLine("HeaderArchiveFileDataStartOffset_UINT32: [{0} BYTES] {1}", Marshal.SizeOf(HeaderArchiveFileDataStartOffset_UINT32), HeaderArchiveFileDataStartOffset_UINT32);
                Console.WriteLine("HeaderFileCount_UINT32: [{0} BYTES] {1}", Marshal.SizeOf(HeaderFileCount_UINT32), HeaderFileCount_UINT32);
                Console.WriteLine("HeaderUnknown1_UINT32: [{0} BYTES] {1}", Marshal.SizeOf(HeaderUnknown1_UINT32), HeaderUnknown1_UINT32);
                Console.WriteLine("HeaderArchiveFileSize_UINT64: [{0} BYTES] {1}", Marshal.SizeOf(HeaderArchiveFileSize_UINT64), HeaderArchiveFileSize_UINT64);
                Console.WriteLine(" - left off at offset: {0}", reader.BaseStream.Position);

                HeaderEncryptedPadding_UINT64s = new ulong[32];

                for (int j = 0; j < 32; j++)
                    HeaderEncryptedPadding_UINT64s[j] = reader.ReadUInt64();

                HeaderUnknown2_UINT64 = reader.ReadUInt64(); //offset 280
                HeaderEncryptedFilePathsStartOffset_UINT64 = reader.ReadUInt64(); //offset 288 //0x120 
                HeaderEncryptedFilePathsSize_UINT64 = reader.ReadUInt64(); //offset 296 //0x128 its size

                Console.WriteLine("HeaderUnknown2_UINT64: [{0} BYTES] {1}", Marshal.SizeOf(HeaderUnknown2_UINT64), HeaderUnknown2_UINT64);
                Console.WriteLine("HeaderBlobOffset_UINT64: [{0} BYTES] {1}", Marshal.SizeOf(HeaderEncryptedFilePathsStartOffset_UINT64), HeaderEncryptedFilePathsStartOffset_UINT64);
                Console.WriteLine("HeaderUnknown3_UINT64: [{0} BYTES] {1}", Marshal.SizeOf(HeaderEncryptedFilePathsSize_UINT64), HeaderEncryptedFilePathsSize_UINT64);
                Console.WriteLine(" - left off at offset: {0}", reader.BaseStream.Position);

                Console.WriteLine("Reading empty byte padding chunk 720 bytes long...", reader.BaseStream.Position);

                HeaderBytePaddingData = new byte[720];

                for (int j = 0; j < HeaderBytePaddingData.Length; j++)
                {
                    HeaderBytePaddingData[j] = (byte)reader.BaseStream.ReadByte();
                }

                Console.WriteLine(" - left off at offset: {0}", reader.BaseStream.Position);

                HeaderArchiveEntries = new FF16_ArchiveEntry[HeaderFileCount_UINT32];

                Console.WriteLine("Reading entries...");

                for (int j = 0; j < HeaderFileCount_UINT32; j++)
                {
                    //EACH ENTRY IS SUPPSOEDLY 56 BYTES LONG
                    HeaderArchiveEntries[j] = new FF16_ArchiveEntry(reader);
                }

                Console.WriteLine(" - left off at offset: {0}", reader.BaseStream.Position);

                HeaderEncryptedFilePaths = new byte[HeaderEncryptedFilePathsSize_UINT64];

                Console.WriteLine("Reading encrypted file paths...");

                long skipLength = reader.BaseStream.Position - (long)HeaderEncryptedFilePathsStartOffset_UINT64;
                Console.WriteLine("Skipping to blob offset ({0} bytes skipped from last position)", skipLength);

                reader.BaseStream.Seek((long)HeaderEncryptedFilePathsStartOffset_UINT64, SeekOrigin.Begin);

                for (int j = 0; j < HeaderEncryptedFilePaths.Length; j++)
                {
                    HeaderEncryptedFilePaths[j] = reader.ReadByte();
                }

                //HeaderUnencryptedFilePaths_NOT_SERIALIZED = new byte[0];
                //HeaderFilePathsString_NOT_SERIALIZED = "";
                NOT_SERIALIZED_HeaderFilePaths = new string[0];
                UnencryptFilePaths();
                GetFilePaths();

                ExtractFiles(reader, "J:\\WRITE-TEST-FF16\\");

                Console.WriteLine(" - left off at offset: {0}", reader.BaseStream.Position);
                Console.WriteLine("entry count {0}", HeaderArchiveEntries.Length);
                Console.WriteLine("unencrypted string count {0}", NOT_SERIALIZED_HeaderFilePaths.Length);

            }
        }
    }

    internal class Program
    {
        public static void PrintJsonOfArchive(string pacFilePath)
        {
            using (StreamWriter file = File.CreateText(pacFilePath + ".json"))
            {
                List<object> jsonObjects = new List<object>();

                FF16_Archive archive = new FF16_Archive(pacFilePath);
                jsonObjects.Add(archive);

                //seralize the data and write it to the configruation file
                JsonSerializer serializer = new JsonSerializer();
                serializer.Formatting = Formatting.Indented;
                serializer.Serialize(file, jsonObjects);
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Paste in folder path of .pac archive files...");
            string pacFolderPath = Console.ReadLine();

            if(Directory.Exists(pacFolderPath) == false)
            {
                Console.WriteLine("Folder path containing .pac archive files doesn't exist!");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Paste in the folder path to extract the archive files into...");
            string writePath = Console.ReadLine();

            if (Directory.Exists(writePath) == false)
            {
                Console.WriteLine("Folder path to extract the archive contents into doesn't exist!");
                Console.ReadKey();
                return;
            }

            //string pacFolderPath = "D:\\SteamLibrary\\steamapps\\common\\FINAL FANTASY XVI DEMO\\data";
            //string writePath = "J:\\WRITE-TEST-FF16\\";

            List<string> pacFilePaths = new List<string>();

            string[] directoryFiles = Directory.GetFiles(pacFolderPath);

            for(int i = 0; i < directoryFiles.Length; i++)
            {
                if (Path.GetExtension(directoryFiles[i]) == ".pac")
                    pacFilePaths.Add(directoryFiles[i]);
            }

            Console.WriteLine("{0} pac files found!", pacFilePaths.Count);

            for (int i = 0; i < pacFilePaths.Count; i++)
            {
                Console.WriteLine("=========================================");
                Console.WriteLine("Reading... {0}", pacFilePaths[i]);

                PrintJsonOfArchive(pacFilePaths[i]);
            }

            Console.ReadLine();
        }
    }
}
