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
import java.util.Iterator;


public class DexFromOat {

    public static boolean dexFromOat(String oatpath, String outdir) {

        try {
            RandomAccessFile oatfile = new RandomAccessFile(oatpath, "r");
            Elf e = Elf.parse(oatfile);
            Oat o = new Oat(e);
            int i = 0;
            for (Iterator<Dex> d = o.dex_files.values().iterator(); d.hasNext();i++){
                Dex dex = d.next();
                dex.write(outdir+"/classes"+i+".dex");
            }

        } catch (ParseException | IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static void main(String[] args) {
        dexFromOat(args[0], args[1]);
    }
}
