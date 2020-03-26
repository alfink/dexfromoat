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

package saarland.cispa.artist.dexfromoat;

import java.io.*;
import java.text.ParseException;

public class Dex {

    private final long dex_offset;
    Oat oat;
    DexFileHeader fileheader;
    HeaderItem header;

    class DexFileHeader{
        public String dex_file_location_str;
        byte[] dex_file_location_size = new byte[4];
        byte[] dex_file_location_data;
        byte[] dex_file_location_checksum = new byte[4];
        byte[] dex_file_pointer = new byte[4];
        byte[][] classes_offsets;

        DexFileHeader(long offset) throws IOException, ParseException {
            long mark = oat.oatfile.getFilePointer();
            oat.oatfile.seek(offset);
            oat.oatfile.read(dex_file_location_size);
            dex_file_location_str = readString(oat.oatfile.getFilePointer(), oat.elf.unpack_int(dex_file_location_size));
            dex_file_location_data = new byte[(int) oat.elf.unpack_int(dex_file_location_size)];
            oat.oatfile.read(dex_file_location_data);
            oat.oatfile.read(dex_file_location_checksum);
            oat.oatfile.read(dex_file_pointer);
            header = new HeaderItem(oat.oatdata_offset + oat.elf.unpack_int(dex_file_pointer));
            classes_offsets = new byte[(int) oat.elf.unpack_int(header.class_defs_size)][4];
            for (int i = 0; i < (int) oat.elf.unpack_int(header.class_defs_size); i++)
                oat.oatfile.read(classes_offsets[i]);
            oat.oatfile.seek(mark);
        }
    }

    public String readString(long offset, long size) throws IOException, ParseException {
        long mark = oat.oatfile.getFilePointer();
        oat.oatfile.seek(offset);
        StringBuilder sb = new StringBuilder();
        int b;
        for(int i = 0; i < size; i++){
            b = oat.oatfile.read();
            if (b == -1){
                throw new ParseException("reached EOF while parsing fixed-size string", (int)oat.oatfile.getFilePointer());
            }
            else {
                sb.append((char) b);
            }
        }
        oat.oatfile.seek(mark);
        return sb.toString();
    }

    class HeaderItem{
        byte[] magic = new byte[8];
        byte[] checksum = new byte[4];
        byte[] signature = new byte[20];
        byte[] file_size = new byte[4];
        byte[] header_size = new byte[4];
        byte[] endian_tag = new byte[4];
        byte[] link_size = new byte[4];
        byte[] link_off = new byte[4];
        byte[] map_off = new byte[4];
        byte[] string_ids_size = new byte[4];
        byte[] string_ids_off = new byte[4];
        byte[] type_ids_size = new byte[4];
        byte[] type_ids_off = new byte[4];
        byte[] proto_ids_size = new byte[4];
        byte[] proto_ids_off = new byte[4];
        byte[] field_ids_size = new byte[4];
        byte[] field_ids_off = new byte[4];
        byte[] method_ids_size = new byte[4];
        byte[] method_ids_off = new byte[4];
        byte[] class_defs_size = new byte[4];
        byte[] class_defs_off = new byte[4];
        byte[] data_size = new byte[4];
        byte[] data_off = new byte[4];

        HeaderItem(long offset) throws IOException {
            long mark = oat.oatfile.getFilePointer();
            oat.oatfile.seek(offset);
            oat.oatfile.read(magic);
            oat.oatfile.read(checksum);
            oat.oatfile.read(signature);
            oat.oatfile.read(file_size);
            oat.oatfile.read(header_size);
            oat.oatfile.read(endian_tag);
            oat.oatfile.read(link_size);
            oat.oatfile.read(link_off);
            oat.oatfile.read(map_off);
            oat.oatfile.read(string_ids_size);
            oat.oatfile.read(string_ids_off);
            oat.oatfile.read(type_ids_size);
            oat.oatfile.read(type_ids_off);
            oat.oatfile.read(proto_ids_size);
            oat.oatfile.read(proto_ids_off);
            oat.oatfile.read(field_ids_size);
            oat.oatfile.read(field_ids_off);
            oat.oatfile.read(method_ids_size);
            oat.oatfile.read(method_ids_off);
            oat.oatfile.read(class_defs_size);
            oat.oatfile.read(class_defs_off);
            oat.oatfile.read(data_size);
            oat.oatfile.read(data_off);
            assert oat.oatfile.getFilePointer() == mark + oat.elf.unpack_int(header_size);
            oat.oatfile.seek(mark);
        }
    }

    public void write(String outfile) throws IOException {
//        System.out.println("extracting dex file: " + fileheader.dex_file_location_str + " (" + oat.elf.unpack_int(header.file_size) + " B) to ./" + outfile);
        File f = new File(outfile);
        f.delete();
        RandomAccessFile out = new RandomAccessFile(outfile, "rw");
        int size = (int) oat.elf.unpack_int(header.file_size);
        oat.oatfile.seek(oat.oatdata_offset + oat.elf.unpack_int(fileheader.dex_file_pointer));
        byte[] data = new byte[size];
        oat.oatfile.read(data);
        out.write(data);
        out.close();
//        System.out.println("done. ");
    }

    Dex(Oat oat, long offset) throws IOException, ParseException {
        this.oat = oat;
        dex_offset = offset;
        fileheader = new DexFileHeader(offset);
        }
}
