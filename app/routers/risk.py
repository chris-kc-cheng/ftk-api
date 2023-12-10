from io import BytesIO
from fastapi import APIRouter, Depends, UploadFile
from fastapi.responses import StreamingResponse
import numpy as np
import pandas as pd
from ..dependencies import db
from .user import get_current_user

router = APIRouter(prefix='/risk',
                   tags=['risk'],
                   dependencies=[Depends(get_current_user)],
                   responses={404: {'description': 'Not found'}})


@router.get("/test")
def test_data_for_charts():
    """
    Line/Bar/Scatter chart:
        dict of 3 lists: index, columns and data
    Pie chart:
        dict of 2 lists: columns and data
    Scatter chart:
    """
    line = pd.DataFrame(np.random.randint(0, 100, size=(10, 2)),
                        columns=['Fund', 'Benchmark'],
                        index=pd.date_range(start='2000-01-01', freq='M', periods=10))
    line.index = line.index.to_series().astype(str)

    scatter = pd.DataFrame(np.random.randint(0, 100, size=(3, 2)), index=[
                           'Fund', 'Benchmark', 'Peer Group'], columns=['Return', 'Volatility'])

    bar = pd.DataFrame(np.random.randint(0, 100, size=(5, 3)),
                       columns=['US/Canada', 'Europe', 'Asia'],
                       index=pd.period_range(start='2023-01', freq='M', periods=5))
    bar.index = bar.index.astype(str)

    pie = pd.Series(np.random.randint(0, 100, size=(3)), index=[
                    'Equity', 'Fixed Income', 'Cash']).to_dict()

    return {
        'lineChartData': line.to_dict(orient='split'),
        'scatterChartData': scatter.to_dict(orient='split'),
        'barChartData': bar.to_dict(orient='split'),
        'pieChartData': {
            'columns': list(pie),
            'data': list(pie.values())
        }
    }

@router.get("/data")
async def download_data():
    """
    Writing DataFrame to memory:
    https://pandas.pydata.org/pandas-docs/version/0.25.0/user_guide/io.html#writing-excel-files-to-memory    
    """
    bio = BytesIO()
    writer = pd.ExcelWriter(bio)
    #df = pd.DataFrame([{"a": 1}, {"a": 2}], index=pd.date_range('2022-12-31', periods=2, freq='M'))
    funds = await db.fund.find({}, {'name': 1}).collation({'locale': 'en' }).sort({'name': 1 }).to_list(1000)
    df = pd.DataFrame(list(funds)).set_index('_id')
    df.to_excel(writer)
    writer.close()
    bio.seek(0)
    return StreamingResponse(bio, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@router.post("/data")
def upload_data(file: UploadFile):
    print(file.filename, file.content_type)
    df = pd.read_excel(file.file)
    print(df)