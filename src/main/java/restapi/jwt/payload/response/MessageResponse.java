package restapi.jwt.payload.response;

public class MessageResponse {
	private String message;
	private boolean status;
	private Object data;
	private Long totalItems;
	private Integer totalPages;
	private Integer currentPage;
	private Integer pageSize;

	public MessageResponse(boolean status, String message, Object data) {
		this.status = status;
		this.message = message;
		this.data=data;
	}
	public MessageResponse(
			boolean status
			, String message
			, Object data
			, Long totalItems
			, Integer totalPages
			, Integer currentPage
			, Integer pageSize) {

		this.status = status;
		this.message = message;
		this.data=data;
		this.totalItems = totalItems;
		this.totalPages = totalPages;
		this.currentPage=currentPage;
		this.pageSize=pageSize;
	}


	public Long getTotalItems() {
		return totalItems;
	}

	public void setTotalItems(Long totalItems) {
		this.totalItems = totalItems;
	}

	public Integer getTotalPages() {
		return totalPages;
	}

	public void setTotalPages(Integer totalPages) {
		this.totalPages = totalPages;
	}

	public Integer getCurrentPage() {
		return currentPage;
	}

	public void setCurrentPage(Integer currentPage) {
		this.currentPage = currentPage;
	}

	public Integer getPageSize() {
		return pageSize;
	}

	public void setPageSize(Integer pageSize) {
		this.pageSize = pageSize;
	}



	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}

	public boolean getStatus(){
		return this.status;
	}
	public void setStatus(boolean status){
		this.status=status;
	}

	public Object getData(){
		return this.data;
	}
	public void setData(Object data){
		this.data=data;
	}
}
