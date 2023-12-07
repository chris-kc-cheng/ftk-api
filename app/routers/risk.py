from fastapi import APIRouter, Depends

router = APIRouter(prefix='/risk',
                   tags=['risk'],
                   dependencies=[],
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