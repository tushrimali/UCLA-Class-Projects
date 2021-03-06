package simpledb;

/**
 * Inserts tuples read from the child operator into the tableid specified in the
 * constructor
 */
public class Insert extends Operator {

    private static final long serialVersionUID = 1L;
    private DbIterator      dbit;
    private TransactionId tid;
    private boolean   flag;
    private int TableId;
    private TupleDesc tupdesc;

    /**
     * Constructor.
     * 
     * @param t
     *            The transaction running the insert.
     * @param child
     *            The child operator from which to read tuples to be inserted.
     * @param tableid
     *            The table in which to insert tuples.
     * @throws DbException
     *             if TupleDesc of child differs from table into which we are to
     *             insert.
     */
    public Insert(TransactionId t,DbIterator child, int tableid)
            throws DbException 
            {
    	  tid = t;
          dbit = child;
          TableId = tableid;
 //         flag = false;
      	
        Type[] type = new Type[]{Type.INT_TYPE};
        String[] name = new String[]{"Number Inserted Records"};
      	tupdesc = new TupleDesc(type, name);
          
    }

    public TupleDesc getTupleDesc() 
    {
    	return tupdesc;
    }

    public void open() throws DbException, TransactionAbortedException 
    {
//   	flag = false;
    	dbit.open();
    }

    public void close() 
    {
    	dbit.close();
    }

    public void rewind() throws DbException, TransactionAbortedException 
    {
    	dbit.rewind();
    }

    /**
     * Inserts tuples read from child into the tableid specified by the
     * constructor. It returns a one field tuple containing the number of
     * inserted records. Inserts should be passed through BufferPool. An
     * instances of BufferPool is available via Database.getBufferPool(). Note
     * that insert DOES NOT need check to see if a particular tuple is a
     * duplicate before inserting it.
     * 
     * @return A 1-field tuple containing the number of inserted records, or
     *         null if called more than once.
     * @see Database#getBufferPool
     * @see BufferPool#insertTuple
     */
    protected Tuple fetchNext() throws TransactionAbortedException, DbException {
        // some code goes here
        return null;
    }

    @Override
    public DbIterator[] getChildren() {
        // some code goes here
        return null;
    }

    @Override
    public void setChildren(DbIterator[] children) {
        // some code goes here
    }
}
