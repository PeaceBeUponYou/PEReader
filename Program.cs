using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PEReader
{
    struct SectionData
    {
        public char[] Name;
        public int VirtualSize;
        public int VirtualAddress;
        public int SizeOfRawData;
        public int PointerToRawData;
        public int PointerToRelocations;
        public int PointerToLineNumbers;
        public short NumberOfRelocations;
        public short NumberOfLineNumbers;
        public int Characteristics; //isExecutible = Characteristics & 0x20
    }
    public struct Exports
    {
        public char[] Name;
        public long offset;
    }
    public struct Imports
    {
        public char[] dllName;
        public List<Exports> functions; //name,offset
        int functionCount;
        public long dataOffset;
        public long thunk;
        public int timeStamp;
        public int forwarder;
        public long NameRVA;
        public long FirstThunk;

    }
    internal class PEExplorer
    {
        enum Dependencies 
        { 
            BaseOfData,
            StackHeapReserves
        }
        FileStream fs;
        List<SectionData> sections = new List<SectionData>();
        public List<Exports> exports = new List<Exports>();
        public List<Imports> imports = new List<Imports>();
        Dictionary<string, long> Positions = new Dictionary<string, long>();
        byte[] fileTypeMZ = new byte[2];
        byte[] fileTypePE = new byte[4];
        byte[] machine = new byte[2]; //'d'=0x64, 'L'=0x32
        byte[] NumberOfSections = new byte[2];
        byte[] TimeStampTable = new byte[4];
        byte[] PointerToSymbolTable = new byte[4];
        byte[] NumberOfSymbolTable = new byte[4];
        byte[] SizeOfOptionalHeader = new byte[2];
        byte[] Characteristics = new byte[2];
        byte[] Magic = new byte[2];
        byte[] MajorLinkerVersion = new byte[1];
        byte[] MinorLinkerVersion = new byte[1];
        byte[] SizeOfCode = new byte[4];
        byte[] SizeOfInitializedData = new byte[4];
        byte[] SizeOfUninitializedData = new byte[4];
        byte[] AddressOfEntryPoint = new byte[4];
        byte[] BaseOfCode = new byte[4];
        byte[] BaseofDatax86 = new byte[4];
        byte[] ImageBasex86 = new byte[4];
        byte[] ImageBasex64 = new byte[8]; //=BaseofDatax86+ImageBasex86
        byte[] SectionAlignment = new byte[4];
        byte[] FileAlignment = new byte[4];
        byte[] MajorOperatingSystemVersion = new byte[2];
        byte[] MinorOperatingSystemVersion = new byte[2];
        byte[] MajorImageVersion = new byte[2];
        byte[] MinorImageVersion = new byte[2];
        byte[] MajorSubsystemVersion = new byte[2];
        byte[] MinorSubsystemVersion = new byte[2];
        byte[] Win32VersionValue = new byte[4];
        byte[] SizeOfImage = new byte[4];
        byte[] SizeOfHeaders = new byte[4];
        byte[] CheckSum = new byte[4];
        byte[] Subsystem = new byte[2];
        byte[] DllCharacteristics = new byte[2];
        //byte[] SizeOfStackReserve = new byte[4/8];//x86=4, x64=8
        //byte[] SizeOfStackCommit = new byte[4/8];
        //byte[] SizeOfHeapReserve = new byte[4/8];
        //byte[] SizeOfHeapCommit = new byte[4/8];
        byte[] LoaderFlags = new byte[4];
        byte[] NumberOfRVAandSizes = new byte[4];
        byte[] ExportTable = new byte[4];
        byte[] SizeOfExportTable = new byte[4];
        byte[] ImportTable = new byte[4];
        byte[] SizeOfImportTable = new byte[4];
        byte[] ResourceTable = new byte[4];
        byte[] SizeOfResourceTable = new byte[4];
        byte[] ExceptionTable = new byte[4];
        byte[] SizeOfExceptionTable = new byte[4];
        byte[] CertificateTable = new byte[4];
        byte[] SizeOfCertificateTable = new byte[4];
        byte[] BaseRelocationTable = new byte[4];
        byte[] SizeOfBaseRelocationTable = new byte[4];
        byte[] Debug = new byte[4];
        byte[] SizeOfDebug = new byte[4];
        byte[] ArchitectureData = new byte[4];
        byte[] SizeOfArchitectureData = new byte[4];
        byte[] GloablaPtr = new byte[4];
        //byte[] _padding = new byte[4];
        byte[] TLSTable = new byte[4];
        byte[] SizeOfTLSTable = new byte[4];
        byte[] LoadConfigTable = new byte[4];
        byte[] SizeOfLoadConfigTable = new byte[4];
        byte[] BoundImport = new byte[4];
        byte[] SizeOfBoundImport = new byte[4];
        byte[] ImportAddressTable = new byte[4];
        byte[] SizeOfImportAddressTable = new byte[4];
        byte[] DelayImportDescriptor = new byte[4];
        byte[] SizeOfDelayImportDescriptor = new byte[4];
        byte[] CLRRuntimeHeader = new byte[4];
        byte[] SizeOfCLRRuntimeHeader = new byte[4];
        //byte[] _padding2 = new byte[4];
        //byte[] _padding3 = new byte[4];
        byte[] Name = new byte[8];
        byte[] VirtualSize = new byte[4];
        byte[] VirtualAddress = new byte[4];
        byte[] SizeOfRawData = new byte[4];
        byte[] PointerToRawData = new byte[4];
        byte[] PointerToRelocations = new byte[4];
        byte[] PointerToLineNumbers = new byte[4];
        byte[] NumberOfRelocations = new byte[2];
        byte[] NumberOfLineNumbers = new byte[4];
        byte[] Characteristics2 = new byte[4];


        public PEExplorer(string filePath)
        {
            fs = File.Open(filePath, FileMode.Open);
            if (fs == null)
                return;
        }
        ~PEExplorer()
        {
            if (fs != null)
                fs.Close();
        }
        public void Initialize()
        {
            if (fs == null)
                return;
            fs.Read(fileTypeMZ, 0, fileTypeMZ.Length); // 'MZ'
            if (BitConverter.ToInt16(fileTypeMZ, 0) != 0x5A4D)
                return; 
            fs.Position = 0x3C;
            byte[] start = new byte[4];
            fs.Read(start, 0, start.Length);

            fs.Position = BitConverter.ToInt32(start);
            Positions.Add("COFFHeader", fs.Position);
            fs.Read(fileTypePE, 0, fileTypePE.Length);// 'PE'
            if (BitConverter.ToInt16(fileTypePE, 0) != 0x4550)
                return;
            fs.Read(machine, 0, machine.Length);
            fs.Read(NumberOfSections, 0, NumberOfSections.Length);
            fs.Read(TimeStampTable, 0, TimeStampTable.Length);
            fs.Read(PointerToSymbolTable, 0, PointerToSymbolTable.Length);
            fs.Read(NumberOfSymbolTable, 0, NumberOfSymbolTable.Length);
            fs.Read(SizeOfOptionalHeader, 0, SizeOfOptionalHeader.Length); 
            fs.Read(Characteristics, 0, Characteristics.Length);
            Positions.Add("OptionalHeader:StandardCOFFFields", fs.Position);
            fs.Read(Magic, 0, Magic.Length);
            fs.Read(MajorLinkerVersion,0, MajorLinkerVersion.Length);
            fs.Read(MinorLinkerVersion, 0, MinorLinkerVersion.Length);
            fs.Read(SizeOfCode, 0, SizeOfCode.Length); 
            fs.Read(SizeOfInitializedData, 0, SizeOfInitializedData.Length);
            fs.Read(SizeOfUninitializedData, 0, SizeOfUninitializedData.Length);
            fs.Read(AddressOfEntryPoint, 0, AddressOfEntryPoint.Length);
            fs.Read(BaseOfCode,0, BaseOfCode.Length);
            InitForDependencies(Dependencies.BaseOfData);
            Positions.Add("OptionalHeader:WindowsSpecificFields", fs.Position);
            fs.Read(SectionAlignment, 0, SectionAlignment.Length);
            fs.Read(FileAlignment, 0, FileAlignment.Length);
            fs.Read(MajorOperatingSystemVersion, 0, MajorOperatingSystemVersion.Length);
            fs.Read(MinorOperatingSystemVersion, 0, MinorOperatingSystemVersion.Length);
            fs.Read(MajorImageVersion, 0, MajorImageVersion.Length);
            fs.Read(MinorImageVersion, 0, MinorImageVersion.Length);
            fs.Read(MajorSubsystemVersion, 0, MajorSubsystemVersion.Length);
            fs.Read(MinorSubsystemVersion, 0, MinorSubsystemVersion.Length);
            fs.Read(Win32VersionValue, 0, Win32VersionValue.Length);
            fs.Read(SizeOfImage, 0, SizeOfImage.Length);
            fs.Read(SizeOfHeaders, 0, SizeOfHeaders.Length);
            fs.Read(CheckSum, 0, CheckSum.Length);
            fs.Read(Subsystem, 0, Subsystem.Length);
            fs.Read(DllCharacteristics, 0, DllCharacteristics.Length);
            InitForDependencies(Dependencies.StackHeapReserves);
            fs.Read(LoaderFlags, 0, LoaderFlags.Length);
            fs.Read(NumberOfRVAandSizes, 0, NumberOfRVAandSizes.Length);
            Positions.Add("DataDirectories", fs.Position);
            if (BitConverter.ToInt32(NumberOfRVAandSizes) != 16)
                return;
            fs.Read(ExportTable, 0, ExportTable.Length);
            fs.Read(SizeOfExportTable, 0, SizeOfExportTable.Length);
            fs.Read(ImportTable, 0, ImportTable.Length);
            fs.Read(SizeOfImportTable, 0, SizeOfImportTable.Length);
            fs.Read(ResourceTable, 0, ResourceTable.Length);
            fs.Read(SizeOfResourceTable, 0, SizeOfResourceTable.Length);
            fs.Read(ExceptionTable, 0, ExceptionTable.Length);
            fs.Read(SizeOfExceptionTable, 0, SizeOfExceptionTable.Length);
            fs.Read(CertificateTable, 0, CertificateTable.Length);
            fs.Read(SizeOfCertificateTable, 0, SizeOfCertificateTable.Length);
            fs.Read(BaseRelocationTable, 0, BaseRelocationTable.Length);
            fs.Read(SizeOfBaseRelocationTable, 0, SizeOfBaseRelocationTable.Length);
            fs.Read(Debug, 0, Debug.Length);
            fs.Read(SizeOfDebug, 0, SizeOfDebug.Length);
            fs.Read(ArchitectureData, 0, ArchitectureData.Length);
            fs.Read(SizeOfArchitectureData, 0, SizeOfArchitectureData.Length);
            fs.Read(GloablaPtr, 0, GloablaPtr.Length);
            fs.Position += 4;
            fs.Read(TLSTable, 0, TLSTable.Length);
            fs.Read(SizeOfTLSTable, 0, SizeOfTLSTable.Length);
            fs.Read(LoadConfigTable, 0, LoadConfigTable.Length);
            fs.Read(SizeOfLoadConfigTable, 0, SizeOfLoadConfigTable.Length);
            fs.Read(BoundImport, 0, BoundImport.Length);
            fs.Read(SizeOfBoundImport, 0, SizeOfBoundImport.Length);
            fs.Read(ImportAddressTable, 0, ImportAddressTable.Length);
            fs.Read(SizeOfImportAddressTable,0, SizeOfImportAddressTable.Length);
            fs.Read(DelayImportDescriptor, 0, DelayImportDescriptor.Length);
            fs.Read(SizeOfDelayImportDescriptor, 0, SizeOfDelayImportDescriptor.Length);
            fs.Read(CLRRuntimeHeader, 0, CLRRuntimeHeader.Length);
            fs.Read(SizeOfCLRRuntimeHeader,0, SizeOfCLRRuntimeHeader.Length);
            fs.Position += 8;
            Positions.Add("SectionTable",fs.Position);
            fs.Read(Name, 0, Name.Length); 
            fs.Read(VirtualSize, 0, VirtualSize.Length);
            fs.Read(VirtualAddress, 0, VirtualAddress.Length);
            fs.Read(SizeOfRawData, 0, SizeOfRawData.Length);
            fs.Read(PointerToRawData,0,PointerToRawData.Length);
            fs.Read(PointerToRelocations, 0,PointerToRelocations.Length);
            fs.Read(PointerToLineNumbers, 0,PointerToLineNumbers.Length);
            fs.Read(NumberOfRelocations, 0, NumberOfRelocations.Length);
            fs.Read(NumberOfLineNumbers, 0, NumberOfLineNumbers.Length);
            fs.Read(Characteristics2, 0,Characteristics2.Length);
        }
        public void EnumSections()
        {
            if (fs == null)
                return;
            long val, imageSectionHeaderPos = 0;
            if (Positions.TryGetValue("OptionalHeader:StandardCOFFFields", out val))
                imageSectionHeaderPos = (long)BitConverter.ToInt16(SizeOfOptionalHeader, 0) + val;
            else
                return;
            long oldPos = fs.Position;
            fs.Position = imageSectionHeaderPos;
            sections.Clear();
            for (short i = 0; i < BitConverter.ToInt16(NumberOfSections); i++)
            {
                SectionData sectionData = new SectionData();
                sectionData.Name = ReadStringOfChars(fs.Position, 8);
                sectionData.VirtualSize = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.VirtualAddress = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.SizeOfRawData = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.PointerToRawData = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.PointerToRelocations = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.PointerToLineNumbers = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sectionData.NumberOfRelocations = BitConverter.ToInt16(ReadByteArrayMaker(0, 2), 0);
                sectionData.NumberOfLineNumbers = BitConverter.ToInt16(ReadByteArrayMaker(0, 2), 0);
                sectionData.Characteristics = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                sections.Add(sectionData);
            }
            fs.Position = oldPos;
        }
        public void EnumExpots()
        {
            exports.Clear();
            long? exportTablePosition = GetVirtualAddress(BitConverter.ToInt32(ExportTable, 0));
            if(exportTablePosition.HasValue)
            {
                long oldPos = fs.Position;
                fs.Position = exportTablePosition.Value + 0x10;
                int OrdinalBase = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                int NoOfFunctionOffsets = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                int NoOfFunctionNames = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                int OrdinalCount = NoOfFunctionOffsets - NoOfFunctionNames;
                long? FuntionOffsetsAdr = GetVirtualAddress(BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0));
                long? FuntionNamesAdr = GetVirtualAddress(BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0));
                if(FuntionNamesAdr.HasValue && FuntionOffsetsAdr.HasValue)
                {
                    for (int i=0; i< OrdinalCount; i++)
                    {

                    }
                    for (int i=0; i< NoOfFunctionNames; i++)
                    {
                        Exports export = new Exports();
                        fs.Position = (long)FuntionOffsetsAdr + i * 4;
                        export.offset = (long)BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                        fs.Position = (long)FuntionNamesAdr + i * 4;
                        int? charpoint = (int)GetVirtualAddress(BitConverter.ToInt32(ReadByteArrayMaker(0, 4)));
                        if(!charpoint.HasValue)
                        {
                            exports.Clear();
                            return;
                        }
                        export.Name = ReadStringOfChars(charpoint.Value,-1,true);
                        exports.Add(export);
                    }
                }
                fs.Position = oldPos;
            }
        }
        public void EnumImports()
        {
            imports.Clear();
            long? importTablePosition = GetVirtualAddress(BitConverter.ToInt32(ImportTable, 0));
            if (importTablePosition.HasValue)
            {
                long oldPos = fs.Position;
                long importTracker = importTablePosition.Value;
                bool tarIf64 = isFile64Bit();
                int jump = (tarIf64) ? 8 : 4;
                while (true)
                {
                    fs.Position = importTracker;
                    Imports import = new Imports();
                    import.thunk = BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                    if (import.thunk == 0)
                        break;
                    import.timeStamp = BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                    import.forwarder = BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                    import.NameRVA = BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                    import.FirstThunk = BitConverter.ToInt32(ReadByteArrayMaker(0, 4));
                    importTracker = fs.Position;
                    import.dllName = ReadStringOfChars((long)GetVirtualAddress((int)import.NameRVA));
                    int offsetForImportFunctions = (int)GetVirtualAddress((int)import.FirstThunk);
                    int count = 0;
                    import.functions = new List<Exports>();
                    while (true)
                    {
                        Exports exports = new Exports();
                        fs.Position = offsetForImportFunctions + count * jump;
                        exports.offset = fs.Position;
                        count++;
                        int currentOff = BitConverter.ToInt32(ReadByteArrayMaker(0, 4), 0);
                        if (currentOff == 0)
                            break;
                        else if (!tarIf64 || BitConverter.ToUInt32(ReadByteArrayMaker(0, 4), 0) != 0x80000000)
                        {
                            int offPos = (int)GetVirtualAddress(currentOff);
                            exports.Name = (offPos > 0 && currentOff > 0) ? ReadStringOfChars(offPos + 2) : new char[1];
                        }
                        else //Ordinal
                        {
                            exports.Name = new char[2];
                            exports.Name[0] = '-';
                            exports.Name[1] = '\0';
                        }
                        import.functions.Add(exports);

                    }
                    imports.Add(import);
                }
                fs.Position = oldPos;
            }

        }
        private char[] ReadStringOfChars(long position, int count = -1,bool shouldReset = false)
        {
            long oldpos = fs.Position;
            byte[] charData;
            if (count == -1)
            {
                fs.Position = position;
                count = 0;
                charData = ReadByteArrayMaker(0, 1);
                while (charData[0] != 0)
                {
                    charData = ReadByteArrayMaker(0, 1);
                    count++;
                }
                
            }
            fs.Position = position;
            charData = ReadByteArrayMaker(0, count);
            char[] outer = new char[charData.Length];
            count = outer.Length;
            foreach (byte b in charData)
            {
                outer[outer.Length - count] = (char)b;
                count--;
            }
            fs.Position = (shouldReset) ? oldpos : fs.Position;
            return outer;
        }
        private bool isFile64Bit()
        {
            if(BitConverter.ToUInt16(machine,0)==0x8664)
                return true;
            return false;
        }
        private void InitForDependencies(Dependencies dep)
        {
            switch(dep)
            {
                case Dependencies.BaseOfData:
                    if (isFile64Bit())
                    {
                        fs.Read(ImageBasex64, 0, ImageBasex64.Length);
                    }
                    else
                    {
                        fs.Read(BaseofDatax86, 0, BaseofDatax86.Length);
                        fs.Read(ImageBasex86, 0, ImageBasex86.Length);
                    }
                    break;
                case Dependencies.StackHeapReserves:
                    if(isFile64Bit())
                    {
                        fs.Read(new byte[8], 0, 8);
                        fs.Read(new byte[8], 0, 8);
                        fs.Read(new byte[8], 0, 8);
                        fs.Read(new byte[8], 0, 8);
                    }else
                    {
                        fs.Read(new byte[4], 0, 4);
                        fs.Read(new byte[4], 0, 4);
                        fs.Read(new byte[4], 0, 4);
                        fs.Read(new byte[4], 0, 4);
                    }
                    break;
                default:
                    break;
            }

        }
        private byte[] ReadByteArrayMaker(int start,int size)
        {
            byte[] bytes = new byte[size];
            fs.Read(bytes, start, size);
            return bytes;
        }
        private long? GetVirtualAddress(int point)
        {
            foreach(SectionData sectionData in sections)
            {
                if( point < (sectionData.VirtualAddress+sectionData.SizeOfRawData))
                    return sectionData.PointerToRawData-sectionData.VirtualAddress+point;
            }
            return null;
        }
    }
    public class PEReader
    {
        public static void Main()
        {
            string pathToFile = "D:\\Games\\Old World\\MonoBleedingEdge\\EmbedRuntime\\mono-2.0-bdwgc.dll";
            PEExplorer pe = new PEExplorer(pathToFile);
            pe.Initialize();
            pe.EnumSections();
            /*pe.EnumExpots();
            foreach(Exports export in pe.exports)
            {
                Console.WriteLine($"{export.offset:X8} - {new string(export.Name)}");
            }*/
            pe.EnumImports();
            foreach (Imports import in pe.imports)
            {
                StringBuilder allFunction = new StringBuilder();
                allFunction.Append('\n');
                foreach (Exports exp in import.functions)
                {
                    allFunction.Append('\t' + exp.offset.ToString("X8") + " - " + new string(exp.Name) + '\n');
                }
                Console.WriteLine($"{new string(import.dllName)}: {allFunction.ToString()}");
            }
        }
    }
}
