package lorentealberto.byss.ccpf.filters;

import java.io.File;

/**
 *
 * @author Alberto Escribano Lorente
 */
public class RaidoFilter extends javax.swing.filechooser.FileFilter{
    @Override
    public boolean accept(File file) {
        return file.isDirectory() || file.getAbsolutePath().endsWith(".raido");
    }
    @Override
    public String getDescription() {
        return "Señala el camino correcto (*.raido)";
    }
}
