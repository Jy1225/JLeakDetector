package se.lexicon;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.spec.RSAOtherPrimeInfo;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.List;
import java.util.Scanner;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class ExceptionExamples {
    public static void main(String[] args) {

        // Unchecked (Runtime) Exception
//        int[] number = {1,2,3,4,5};
//        System.out.println(number[10]);


        // Checked (Compile Time) Exception
//        Path filePath = Paths.get("folder/TestHere.txt");
//        BufferedReader reader = Files.newBufferedReader(filePath);

        // LocalDate localDate = takeDate.get();
        // System.out.println(localDate);

        /*try {
            ex7();
        } catch (InsufficientFundsException e) {
            throw new RuntimeException(e);
        }*/

        writeRextToFile();

    }

    public static void ex1(){

        while (true) {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter a score between 1-100: ");

            try {

                int score = Integer.parseInt(scanner.nextLine());

                if (score >= 101) {
                    System.out.println("You scored " + score + " Score should be maximum 100");
                } else if (score <= 0) {
                    System.out.println("You scored " + score + " should not be zero or negative");
                }

            }catch (NumberFormatException e){
                System.out.println("Enter a valid number: ");
                //e.printStackTrace();
            }
        }
    }

    public static void ex2(){
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Enter your birthDate (YYYY-MM-DD): ");

            try {
                String input = scanner.nextLine();
                LocalDate date = LocalDate.parse(input);
                System.out.println(date);

            }catch (DateTimeException e) {
                // e.printStackTrace();
                System.out.println("Invalid date format. Please enter date in yyyy-mm-dd format. " + e.getMessage());
            }
        }
        }

    public static Supplier<LocalDate> takeDate = () -> {
        Scanner scanner = new Scanner(System.in);
        LocalDate date = null;

        while (true) {
            System.out.println("Enter your birthDate (YYYY-MM-DD): ");

            try {
                String input = scanner.nextLine();
                date = LocalDate.parse(input);
                break;

            }catch (DateTimeException e) {
                // e.printStackTrace();
                System.out.println("Invalid date format. Please enter date in yyyy-mm-dd format. " + e.getMessage());
            }
        }
        return date;
    };

    //   NIO (Non-Blocking style, reactive. - Not Covered much here.)

    //Checked (Compile Time) Exception
    //Files I/O, NIO
    public static void ex4(){
        //java.io
        //java.nio

        // Path filePath = Paths.get("D:\\lexicon\\Java\\exceptions-files-lecture\\Folder\\lastnames.txt");
        Path filePath = Paths.get("Folder/lastnames.txt");

        try {
            BufferedReader reader = Files.newBufferedReader(filePath);

            // List<String> lastnames = reader.lines().toList();
            //lastnames.forEach(System.out::println);

            Stream<String> lines = Files.lines(filePath);
            lines.forEach(System.out::println);

        }catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Copy an Image to another folder using NIO
    public static void ex5(){

        Path sourceFile = Paths.get("source/baby-groot-4k-2018-96.jpg");
        Path destinationPath =Paths.get("destination");

        try {
            Files.copy(sourceFile, destinationPath.resolve(sourceFile.getFileName())
                    , StandardCopyOption.REPLACE_EXISTING
                    , StandardCopyOption.COPY_ATTRIBUTES
            );
            //Specific Exception -> General Exception
        } catch (NoSuchFileException e) {
            System.out.println("File Path does not exist: " + e);
        } catch (FileAlreadyExistsException e) {
            System.out.println("File Already Exists: " + e);
        } catch (IOException e){
            System.out.println("IO Exception: " + e);
        }
    }

    //Throw an exception with "throw" keyword
    public static void ex6(){

        Scanner sc = new Scanner(System.in);

        System.out.println("Enter number 1: ");
        int number1 = sc.nextInt();
        System.out.println("Enter number 2: ");
        int number2 = sc.nextInt();

        if (number2 == 0) {
            throw new ArithmeticException("Number 2 should not be Zero.");
        }

        int result = number1 / number2;
        System.out.println("result = " + result);

    }

    //Throw our own Exception
    // and Throws Keyword
    //Mathematical it's okay, it's not okay in our bank transaction.(Business Logic)
    public static void ex7() throws InsufficientFundsException{

        double balance = 100;
        double amount = 150;
        System.out.println("Operation - Withdraw");
        System.out.println("Current balance: " + balance);
        System.out.println("Withdraw Amount: " + amount);

        if(amount > balance){
            throw new InsufficientFundsException(balance,amount,"Balance is Insufficient...");
        }

        balance = balance - amount;
        System.out.println("Current balance: " + balance);
    }
        // throw: is used to throw an exception or exceptional event(propagate the exception to a higher-lever).
        // throws: is used to indicate that a method might throw one or more exceptions -- What about checked vs unchecked

    public static void writeRextToFile(){

        Path relativePath = Paths.get("Folder/TextHere.txt");
      
        try {
            BufferedWriter bufferedWriter = Files.newBufferedWriter(relativePath);
            bufferedWriter.write("HELO BODY");
            bufferedWriter.newLine();
            bufferedWriter.close();
        } catch (IOException e) {
            System.out.println("An I/O Exception occurred: " + e.getMessage());
        }


    }



    }
