
def NLS_FUNC(Satirlar, Bölüm, DosyaAdi):
    from openpyxl import Workbook
    wb = Workbook()

    ws = wb.active
    ws.title = Bölüm
    # ws = wb.create_sheet(Bölüm)
    for x in Satirlar:
        ws.append(x)

    wb.save(DosyaAdi)
