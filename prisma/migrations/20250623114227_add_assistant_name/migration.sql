/*
  Warnings:

  - Made the column `assistantName` on table `AssistantID` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "AssistantID" ALTER COLUMN "assistantName" SET NOT NULL;
