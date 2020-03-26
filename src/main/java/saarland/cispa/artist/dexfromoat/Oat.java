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

import saarland.cispa.artist.dexfromoat.elf.Elf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.text.ParseException;
import java.util.HashMap;

public class Oat {

    byte[] magic = new byte[4];
    byte[] version = new byte[4];
    byte[] adler32_checksum = new byte[4];
    byte[] instruction_set = new byte[4];
    byte[] instruction_set_features = new byte[4];
    byte[] dex_file_count = new byte[4];
    byte[] executable_offset = new byte[4];
    byte[] interpreter_to_interpreter_bridge_offset = new byte[4];
    byte[] interpreter_to_compiled_code_bridge_offset = new byte[4];
    byte[] jni_dlsym_lookup_offset_ = new byte[4];
    byte[] portable_imt_conflict_trampoline_offset = new byte[4];
    byte[] portable_resolution_trampoline_offset = new byte[4];
    byte[] portable_to_interpreter_bridge_offset = new byte[4];
    byte[] quick_generic_jni_trampoline_offset = new byte[4];
    byte[] quick_imt_conflict_trampoline_offset = new byte[4];
    byte[] quick_resolution_trampoline_offset = new byte[4];
    byte[] quick_to_interpreter_bridge_offset = new byte[4];
    /*byte[] image_patch_delta = new byte[4];
    byte[] image_file_location_oat_checksum = new byte[4];
    byte[] image_file_location_oat_data_begin = new byte[4];*/
    byte[] key_value_store_size = new byte[4];
    byte[] key_value_store;  // ubyte[key_value_store_size]



    RandomAccessFile oatfile;
    Elf elf;
    private long dex_headers_offset;
    public HashMap<String, Dex> dex_files;
    long oatdata_offset;

    void parseOatHeader(long offset) throws IOException {
        oatdata_offset = offset;
        long mark = oatfile.getFilePointer();
        oatfile.seek(offset);
        oatfile.read(magic);
        oatfile.read(version);
        oatfile.read(adler32_checksum);
        oatfile.read(instruction_set);
        oatfile.read(instruction_set_features);
        oatfile.read(dex_file_count);
        oatfile.read(executable_offset);
        oatfile.read(interpreter_to_interpreter_bridge_offset);
        oatfile.read(interpreter_to_compiled_code_bridge_offset);
        oatfile.read(jni_dlsym_lookup_offset_);
        oatfile.read(portable_imt_conflict_trampoline_offset);
        oatfile.read(portable_resolution_trampoline_offset);
        oatfile.read(portable_to_interpreter_bridge_offset);
        oatfile.read(quick_generic_jni_trampoline_offset);
        oatfile.read(quick_imt_conflict_trampoline_offset);
        oatfile.read(quick_resolution_trampoline_offset);
        oatfile.read(quick_to_interpreter_bridge_offset);
        /*oatfile.read(image_patch_delta);
        oatfile.read(image_file_location_oat_checksum);
        oatfile.read(image_file_location_oat_data_begin);*/
        oatfile.read(key_value_store_size);
        key_value_store = new byte[(int) elf.unpack_int(key_value_store_size)];
        oatfile.read(key_value_store);
        dex_headers_offset = oatfile.getFilePointer();
        oatfile.seek(mark);
    }



    void parseDexFiles() throws IOException, ParseException {
        dex_files = new HashMap<>();
        long offset = dex_headers_offset;
        for (int i = 0; i < elf.unpack_int(dex_file_count); i++){
            Dex d = new Dex(this, offset);
            //offset += d.file_size;
            dex_files.put(d.fileheader.dex_file_location_str, d);
            break;
        }
    }

    Oat(Elf elf) throws IOException, ParseException {
        this.elf = elf;
        this.oatfile = elf.elffile;
        long offset = elf.unpack_int(elf.symbols.get("oatdata").st_value);
        parseOatHeader(offset);
        parseDexFiles();
    }

}
