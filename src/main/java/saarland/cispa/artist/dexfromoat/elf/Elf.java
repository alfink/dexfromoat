/**
 * The ARTist Project (https://artist.cispa.saarland)
 *
 * Copyright (C) 2020 CISPA (https://cispa.saarland), Saarland University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author "Alexander Fink <alexander.fink@cispa.saarland>"
 *
 */
package saarland.cispa.artist.dexfromoat.elf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.text.ParseException;
import java.util.HashMap;

public abstract class Elf {

    public RandomAccessFile elffile;
    private SectionHeader shstrtab_header;

    protected byte[] word() {
        throw new RuntimeException("not implemented: Elf.word()");
    }

    protected ISymbol symbol(long offset) throws IOException, ParseException {
        throw new RuntimeException("not implemented: Elf.symbol()");
    }

    byte[] e_ident_mag = new byte[4];
    byte[] e_ident_class = new byte[1];
    byte[] e_ident_data = new byte[1];
    byte[] e_ident_version = new byte[1];
    byte[] e_ident_osabi = new byte[1];
    byte[] e_ident_abiversion = new byte[1];
    byte[] e_ident_pad = new byte[7];
    byte[] e_type = new byte[2];
    byte[] e_machine = new byte[2];
    byte[] e_version = new byte[4];
    byte[] e_entry = this.word();
    byte[] e_phoff = this.word();
    byte[] e_shoff = this.word();
    byte[] e_flags = new byte[4];
    byte[] e_ehsize = new byte[2];
    byte[] e_phentsize = new byte[2];
    byte[] e_phnum = new byte[2];
    byte[] e_shentsize = new byte[2];
    byte[] e_shnum = new byte[2];
    byte[] e_shstrndx = new byte[2];

    HashMap<String, SectionHeader> sections = new HashMap<>();
    public HashMap<String, ISymbol> symbols = new HashMap<>();



    public static Elf parse(RandomAccessFile elffile) throws IOException, ParseException {
        elffile.seek(4);
        int val = elffile.read();
        switch (val){
            case 1:
                return new Elf32(elffile);
            case 2:
                return new Elf64(elffile);
            default:
                throw new ParseException("Illegal value for e_ident_class: " + val, 4);
        }
    }

    void parse_elf() throws IOException, ParseException {
        parse_elf_header();
        parse_sections();
        parse_dynsyms();
    }

    void parse_elf_header() throws IOException, ParseException {
        elffile.seek(0);
        elffile.read(e_ident_mag);
        elffile.read(e_ident_class);
        elffile.read(e_ident_data);
        elffile.read(e_ident_version);
        elffile.read(e_ident_osabi);
        elffile.read(e_ident_abiversion);
        elffile.read(e_ident_pad);
        elffile.read(e_type);
        elffile.read(e_machine);
        elffile.read(e_version);
        elffile.read(e_entry);
        elffile.read(e_phoff);
        elffile.read(e_shoff);
        elffile.read(e_flags);
        elffile.read(e_ehsize);
        elffile.read(e_phentsize);
        elffile.read(e_phnum);
        elffile.read(e_shentsize);
        elffile.read(e_shnum);
        elffile.read(e_shstrndx);
    }

    public long unpack_int(byte[] data){
        long val = 0;
        for (int i = 0; i < data.length; i++) {
            if (e_ident_data[0] == 2) {
                val = val*256 + (data[i] & 0xFF);
            }
            else {
                val = val*256 + (data[data.length-1-i] & 0xFF);
            }
        }
        return val;
    }

    class SectionHeader{

        byte[] sh_name = new byte[4];
        String sh_name_str = null;
        byte[] sh_type = new byte[4];
        byte[] sh_flags = word();
        byte[] sh_addr = word();
        byte[] sh_offset = word();
        byte[] sh_size = word();
        byte[] sh_link = new byte[4];
        byte[] sh_info = new byte[4];
        byte[] sh_addralign = word();
        byte[] sh_entsize = word();

        SectionHeader(long offset) throws IOException, ParseException {
            long mark = elffile.getFilePointer();
            elffile.seek(offset);
            elffile.read(sh_name);
            if (offset != unpack_int(e_shoff) + unpack_int(e_shstrndx) * unpack_int(e_shentsize)){
                sh_name_str = lookup_shstrtab(unpack_int(sh_name));
            } else {
                sh_name_str = ".shstrtab";
            }
            elffile.read(sh_type);
            elffile.read(sh_flags);
            elffile.read(sh_addr);
            elffile.read(sh_offset);
            elffile.read(sh_size);
            elffile.read(sh_link);
            elffile.read(sh_info);
            elffile.read(sh_addralign);
            elffile.read(sh_entsize);
            elffile.seek(mark);
        }

    }

    public abstract class ISymbol {
        public byte[] st_name = new byte[4];
        public String st_name_str = null;
        public byte[] st_value = word();
        public byte[] st_size = word();
        public byte[] st_info = new byte[1];
        public byte[] st_other = new byte[1];
        public byte[] st_shndx = new byte[2];
    }

    public String readCString(long offset) throws IOException, ParseException {
        long mark = elffile.getFilePointer();
        elffile.seek(offset);
        StringBuilder sb = new StringBuilder();
        int b;
        while((b = elffile.read()) != -1){
            if (b == 0){
                elffile.seek(mark);
                return sb.toString();
            }
            else {
                sb.append((char) b);
            }
        }
        throw new ParseException("reached EOF while parsing CString", (int)elffile.getFilePointer());
    }

    String lookup_shstrtab(long offset) throws IOException, ParseException {
        if (shstrtab_header == null) {
            long header_offset = unpack_int(e_shoff) + unpack_int(e_shstrndx) * unpack_int(e_shentsize);
            shstrtab_header = new SectionHeader(header_offset);
        }
        return readCString(unpack_int(shstrtab_header.sh_offset) + offset);
    }

    String lookup_dynstr(long offset) throws IOException, ParseException {
        return readCString(unpack_int(sections.get(".dynstr").sh_offset) + offset);
    }

    void parse_dynsyms() throws IOException, ParseException {
        symbols = new HashMap<>();
        SectionHeader dynsym = sections.get(".dynsym");
        for (long i = 0; i * unpack_int(dynsym.sh_entsize) < unpack_int(dynsym.sh_size); i++){
            long offset = i  * unpack_int(dynsym.sh_entsize) + unpack_int(dynsym.sh_offset);
            ISymbol a = symbol(offset);
//            System.out.println("Symbol: " + a.st_name_str);
            symbols.put(a.st_name_str, a);
        }
    }

    void parse_sections() throws IOException, ParseException {
        sections = new HashMap<>();
        for (int header = 0; header < unpack_int(e_shnum); header++) {
            long offset = unpack_int(e_shoff) + header*unpack_int(e_shentsize);
            SectionHeader sh = new SectionHeader(offset);
            sections.put(sh.sh_name_str, sh);
//            System.out.println("Section '" + ((sh.sh_name_str != null)?sh.sh_name_str:"") + "' at " + offset);
        }
    }

}
