import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

// ── CSV Export ─────────────────────────────────────────────────
function toCsvString(headers: string[], rows: string[][]): string {
  const escape = (v: string) =>
    v.includes(",") || v.includes('"') || v.includes("\n")
      ? `"${v.replace(/"/g, '""')}"`
      : v;
  return [
    headers.map(escape).join(","),
    ...rows.map((r) => r.map(escape).join(",")),
  ].join("\n");
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportCsv(
  filename: string,
  headers: string[],
  rows: string[][]
) {
  downloadBlob(toCsvString(headers, rows), filename, "text/csv;charset=utf-8;");
}

// ── PDF Export ─────────────────────────────────────────────────
interface PdfSection {
  title: string;
  headers: string[];
  rows: string[][];
}

export function exportPdf(filename: string, sections: PdfSection[]) {
  const doc = new jsPDF({ orientation: "landscape" });

  // Title
  doc.setFontSize(18);
  doc.setTextColor(0, 200, 120);
  doc.text("SENTINEL — Analytics Report", 14, 18);
  doc.setFontSize(9);
  doc.setTextColor(140, 140, 140);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 25);

  let startY = 32;

  for (const section of sections) {
    doc.setFontSize(12);
    doc.setTextColor(60, 60, 60);
    doc.text(section.title, 14, startY);
    startY += 4;

    autoTable(doc, {
      startY,
      head: [section.headers],
      body: section.rows,
      theme: "grid",
      styles: { fontSize: 8, cellPadding: 2, font: "courier" },
      headStyles: {
        fillColor: [20, 30, 40],
        textColor: [0, 200, 120],
        fontStyle: "bold",
      },
      alternateRowStyles: { fillColor: [245, 245, 250] },
      margin: { left: 14, right: 14 },
    });

    startY = (doc as any).lastAutoTable.finalY + 12;

    // Add page if running out of space
    if (startY > 170) {
      doc.addPage();
      startY = 18;
    }
  }

  doc.save(filename);
}
