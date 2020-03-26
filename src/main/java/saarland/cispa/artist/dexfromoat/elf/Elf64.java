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

public class Elf64 extends Elf {


    public Elf64(RandomAccessFile elffile) throws IOException, ParseException {
        this.elffile = elffile;
        this.parse_elf();
    }


    public byte[] word(){
        return new byte[8];
    }

    class Symbol64 extends ISymbol {

        Symbol64(long offset) throws IOException, ParseException {
            long mark = elffile.getFilePointer();
            elffile.seek(offset);
            elffile.read(st_name);
            st_name_str = lookup_dynstr(unpack_int(st_name));
            elffile.read(st_info);
            elffile.read(st_other);
            elffile.read(st_shndx);
            elffile.read(st_value);
            elffile.read(st_size);
            elffile.seek(mark);
        }
    }

    public ISymbol symbol(long offset) throws IOException, ParseException {
        return new Symbol64(offset);
    }

}
