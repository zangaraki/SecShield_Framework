package MyProject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Random;
import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.ss.usermodel.*;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.FormulaEvaluator;
import org.apache.poi.ss.usermodel.Row;

public class ReadWriteExcelFile {

    public static int FindInExcel(String XLSfileName, int SheetNumber, int rowID) throws IOException {
        Random random=new Random();
        int r=random.nextInt(6);
        String current = new java.io.File(".").getCanonicalPath();
        String excelFilePath = current + "\\" + XLSfileName;

        System.out.println("Read from Excel: " + excelFilePath);

        //obtaining input bytes from a file  
        //FileInputStream fis = new FileInputStream(new File(excelFilePath));
        FileInputStream fis = new FileInputStream(new File(XLSfileName));
        //creating workbook instance that refers to .xls file  
        HSSFWorkbook wb = new HSSFWorkbook(fis);
        //creating a Sheet object to retrieve the object  
        HSSFSheet sheet = wb.getSheetAt(SheetNumber);
        //evaluating cell type   
        FormulaEvaluator formulaEvaluator = wb.getCreationHelper().createFormulaEvaluator();

        int row_counter = 0;
        for (Row row : sheet) {
            if (SheetNumber == 0) {
                int cell_counter = 0;
                for (Cell cell : row) {
                    switch (formulaEvaluator.evaluateInCell(cell).getCellType()) {
                        case Cell.CELL_TYPE_NUMERIC:
                            //field that represents numeric cell type  
                            //getting the value of the cell as a number  
                            switch (cell_counter) {
                                case 0:
                                    Config.vmID = (int) cell.getNumericCellValue();
                                     if(r==cell_counter)Config.sub_att=Integer.toString(Config.vmID);
                                    //Config.sub_att+=Integer.toString(Config.vmID);
                                    break;
                                case 1:
                                    Config.Source = (int) cell.getNumericCellValue();
                                    if(r==cell_counter)Config.sub_att=Integer.toString(Config.Source);
                                    //Config.sub_att+=Integer.toString(Config.Source);
                                    break;
                                case 2:
                                    Config.Age = (int) cell.getNumericCellValue();
                                    if(r==cell_counter)Config.sub_att=Integer.toString(Config.Age);
                                    //Config.sub_att+=Integer.toString(Config.Age);
                                    break;
                                case 3:
                                    Config.Sensivity = (int) cell.getNumericCellValue();
                                    if(r==cell_counter)Config.sub_att=Integer.toString(Config.Sensivity);
                                    //Config.sub_att+=Integer.toString(Config.Sensivity);
                                    break;
                                
                                default:
                            }

                        case Cell.CELL_TYPE_STRING:
                            //field that represents string cell type  
                            //getting the value of the cell as a string
                            switch (cell_counter){
                                case 4:
                                    Config.Role=cell.getStringCellValue();
                                    if(r==cell_counter)Config.sub_att=Config.Role;
                                    //Config.sub_att+=Config.Role;
                                    break;
                                case 5:
                                    Config.Specialty=cell.getStringCellValue();
                                    if(r==cell_counter)Config.sub_att=Config.Specialty;
                                    //Config.sub_att+=Config.Specialty;
                                    break;
                                
                            }
                            break;
                    }
                    cell_counter++;
                }
                if (Config.vmID == rowID) {
                    System.out.println("vmID: " + Config.vmID + "  Source: " + Config.Source
                            + "  Age: " + Config.Age + "  Sensivity: " + Config.Sensivity+ "Role: "+Config.Role+ "Specialty:"+Config.Specialty);
                    break;
                }
            } else if (SheetNumber == 1) {
                int cell_counter = 0;
                for (Cell cell : row) {
                    switch (formulaEvaluator.evaluateInCell(cell).getCellType()) {
                        case Cell.CELL_TYPE_NUMERIC:
                            //field that represents numeric cell type  
                            //getting the value of the cell as a number  
                            switch (cell_counter) {
                                case 0:
                                    Config.ID = (int) cell.getNumericCellValue();
                                    if(r==cell_counter)Config.obj_att=Integer.toString(Config.ID);
                                    //Config.obj_att+=Integer.toString(Config.ID);
                                    break;
                                case 3:
                                    Config.DOMAIN = (int) cell.getNumericCellValue();
                                    if(r==cell_counter)Config.obj_att=Integer.toString(Config.DOMAIN);
                                    //Config.obj_att+=Integer.toString(Config.DOMAIN);
                                    break;
                                case 4:
                                    Config.securityLabel=(int)cell.getNumericCellValue();;
                                     if(r==cell_counter)Config.obj_att=Integer.toString(Config.securityLabel);
                                    //Config.obj_att+=Integer.toString(Config.securityLabel);
                                default:
                            }

                        case Cell.CELL_TYPE_STRING:
                            //field that represents string cell type  
                            //getting the value of the cell as a string  
                            switch (cell_counter) {
                                case 1:
                                    Config.URI = cell.getStringCellValue();
                                    if(r==cell_counter)Config.obj_att=Config.URI;
                                    //Config.obj_att+=Config.URI;
                                    break;
                                case 2:
                                    Config.IP = cell.getStringCellValue();
                                    if(r==cell_counter)Config.obj_att=Config.IP;
                                    //Config.obj_att+=Config.IP;
                                    break;
                                default:
                            }
                            break;
                    }
                    cell_counter++;
                }
                if (Config.ID == rowID) {
                    System.out.println("ID: " + Config.ID + "  URI: " + Config.URI
                            + "  URI: " + Config.IP + "  DOMAIN: " + Config.DOMAIN  +" securityLabel"  + Config.securityLabel);
                    break;
                }

            }
        }
        fis.close();
        wb.close();
        return -1; // Not found
    }

    public static List<List<String>> ReadFromExcel(String XLSfileName, int SheetNumber) throws IOException {

        List<List<String>> Out_string = new ArrayList<>();

        String current = new java.io.File(".").getCanonicalPath();
        String excelFilePath = current + "\\" + XLSfileName;
        System.out.println("Read from Excel: " + excelFilePath);

        //obtaining input bytes from a file  
        FileInputStream fis = new FileInputStream(new File(excelFilePath));
        //creating workbook instance that refers to .xls file  
        HSSFWorkbook wb = new HSSFWorkbook(fis);
        //creating a Sheet object to retrieve the object  
        HSSFSheet sheet = wb.getSheetAt(SheetNumber);
        //evaluating cell type   
        FormulaEvaluator formulaEvaluator = wb.getCreationHelper().createFormulaEvaluator();

        for (Row row : sheet) //iteration over row using for each loop  
        {
            List<String> string_row = new ArrayList<>();
            for (Cell cell : row) //iteration over cell using for each loop              {                                
            {
                switch (formulaEvaluator.evaluateInCell(cell).getCellType()) {
                    case Cell.CELL_TYPE_NUMERIC:
                        //field that represents numeric cell type  
                        //getting the value of the cell as a number  
                        System.out.print(cell.getNumericCellValue() + "\t\t");
                        break;
                    case Cell.CELL_TYPE_STRING:
                        //field that represents string cell type  
                        //getting the value of the cell as a string  
                        System.out.print(cell.getStringCellValue() + "\t\t");
                        string_row.add(cell.getStringCellValue());
                        break;
                }
            }
            System.out.println();
            Out_string.add(string_row);
        }
        System.out.println("Data is imported!");
        return Out_string;
    }

    public static void updateXLSfile(List<String> str, String XLSfileName) throws IOException, InvalidFormatException {
        String current = new java.io.File(".").getCanonicalPath();
        String excelFilePath = current + "\\" + XLSfileName;

        try {
            FileInputStream inputStream = new FileInputStream(new File(excelFilePath));
            Workbook workbook = WorkbookFactory.create(inputStream);

            Sheet sheet = workbook.getSheetAt(0);

            int rowCount = sheet.getLastRowNum();
            Row row = sheet.createRow(++rowCount);
            int columnCount = 0;

            for (int i = 0; i < str.size(); i++) {
                Cell cell = row.createCell(columnCount++);
                cell.setCellValue(str.get(i));
            }

            inputStream.close();

            FileOutputStream outputStream = new FileOutputStream(current + "\\" + XLSfileName);
            workbook.write(outputStream);
            workbook.close();
            outputStream.close();

        } catch (IOException | EncryptedDocumentException ex) {
            ex.printStackTrace();
        }
    }

    public static void updateXLSfile_Column(List<String> str, String XLSfileName) throws IOException, InvalidFormatException {
        String current = new java.io.File(".").getCanonicalPath();
        String excelFilePath = current + "\\" + XLSfileName;

        try {
            FileInputStream inputStream = new FileInputStream(new File(excelFilePath));
            Workbook workbook = WorkbookFactory.create(inputStream);

            Sheet sheet = workbook.getSheetAt(1);

            int rowCount = sheet.getLastRowNum();
            Row row = sheet.createRow(++rowCount);
            int columnCount = 0;

            for (int i = 0; i < str.size(); i++) {
                Cell cell = row.createCell(columnCount++);
                cell.setCellValue(str.get(i));
            }

            inputStream.close();

            FileOutputStream outputStream = new FileOutputStream(current + "\\" + XLSfileName);
            workbook.write(outputStream);
            workbook.close();
            outputStream.close();

        } catch (IOException | EncryptedDocumentException ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {

        //System.out.println(excelFilePath);
        FindInExcel("Network_access.xls", 1, 60);

    }

}
